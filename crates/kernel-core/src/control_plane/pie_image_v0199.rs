//! V0.19.9 static ELF64 AArch64 ET_DYN/PIE trusted-package admission.
//!
//! Rejects legacy ET_EXEC, PT_DYNAMIC, PT_INTERP, executable stacks, W+X,
//! invalid LOAD/RELRO ranges and non-relative dynamic relocations. The caller
//! must first make an *exclusive, immutable* bounded copy of the registered
//! package and supply its separately frozen manifest SHA-256. This parser
//! never writes or publishes user mappings, never grants task capabilities
//! and never treats a hash match as a complete trusted launch proof.
use sha2::{Digest, Sha256};
use super::Error;

pub const MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;
pub const PAGE_BYTES: u64 = 4096;
pub const MAX_HEADERS: usize = 16;
pub const MAX_RELOCATIONS: usize = 512;
pub const MACHINE_AARCH64: u16 = 183;
pub const TYPE_DYN: u16 = 3;
pub const R_AARCH64_RELATIVE: u64 = 1027;

const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const PT_PHDR: u32 = 6;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

fn le16(b:&[u8],at:usize)->Result<u16,Error>{
    let s=b.get(at..at+2).ok_or(Error::Invalid)?;
    Ok(u16::from_le_bytes([s[0],s[1]]))
}
fn le32(b:&[u8],at:usize)->Result<u32,Error>{
    let s=b.get(at..at+4).ok_or(Error::Invalid)?;
    Ok(u32::from_le_bytes([s[0],s[1],s[2],s[3]]))
}
fn le64(b:&[u8],at:usize)->Result<u64,Error>{
    let s=b.get(at..at+8).ok_or(Error::Invalid)?;
    Ok(u64::from_le_bytes([s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7]]))
}
fn range_end(start:u64,length:u64)->Result<u64,Error>{
    start.checked_add(length).ok_or(Error::Invalid)
}
fn within(start:u64,len:u64,outer_start:u64,outer_end:u64)->bool{
    start>=outer_start
        && range_end(start,len).is_ok_and(|end|end<=outer_end)
}

#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct LoadSegment {
    pub virtual_address:u64,
    pub file_offset:u64,
    pub file_bytes:u64,
    pub memory_bytes:u64,
    pub flags:u32,
}
impl LoadSegment {
    fn writable(self)->bool{self.flags&PF_W!=0}
    fn executable(self)->bool{self.flags&PF_X!=0}
    fn contains_memory(self,start:u64,bytes:u64)->bool{
        within(start,bytes,self.virtual_address,
            self.virtual_address.saturating_add(self.memory_bytes))
    }
    fn contains_file(self,start:u64,bytes:u64)->bool{
        within(start,bytes,self.virtual_address,
            self.virtual_address.saturating_add(self.file_bytes))
    }
}
#[derive(Clone,Copy)]
pub struct PieImage<'a> {
    pub verified_bytes:&'a [u8],
    pub entry:u64,
    pub loads:[Option<LoadSegment>;MAX_HEADERS],
    pub load_count:usize,
    pub relro:Option<(u64,u64)>,
    pub has_executable_stack:bool,
}

/// A build-controlled sidecar entry; the type and symbol index are checked,
/// never interpreted as a dynamic-symbol or external-link lookup.
#[derive(Clone,Copy,Debug)]
pub struct RelativeRelocation{
    pub offset:u64,
    pub info:u64,
    pub addend:i64,
}
impl<'a> PieImage<'a> {
    pub fn parse_verified(
        bytes:&'a[u8],
        expected_manifest_sha256:[u8;32],
    )->Result<Self,Error>{
        if bytes.len()<64 || bytes.len()>MAX_IMAGE_BYTES
            || expected_manifest_sha256==[0;32]
            || bytes.get(0..4)!=Some(&b"\x7fELF"[..])
            || bytes[4]!=2 || bytes[5]!=1 || bytes[6]!=1
            || le16(bytes,16)?!=TYPE_DYN
            || le16(bytes,18)?!=MACHINE_AARCH64
            || le32(bytes,20)?!=1
            || le16(bytes,52)?!=64
            || le16(bytes,54)?!=56
        {return Err(Error::Invalid);}
        let mut h=Sha256::new();h.update(bytes);
        let actual:[u8;32]=h.finalize().into();
        if actual!=expected_manifest_sha256{return Err(Error::Denied);}
        let ph_off=le64(bytes,32)?;
        let ph_num=usize::from(le16(bytes,56)?);
        if ph_num==0 || ph_num>MAX_HEADERS{return Err(Error::Invalid);}
        let table_start=usize::try_from(ph_off).map_err(|_|Error::Invalid)?;
        let table_end=table_start.checked_add(ph_num*56).ok_or(Error::Invalid)?;
        if table_end>bytes.len(){return Err(Error::Invalid);}
        let entry=le64(bytes,24)?;
        if entry==0 || entry%4!=0{return Err(Error::Invalid);}
        let mut loads: [Option<LoadSegment>; MAX_HEADERS] = [None; MAX_HEADERS];
        let mut count=0usize;
        let mut relro=None;
        let mut phdr=None;
        let mut stack_seen=false;
        for i in 0..ph_num {
            let at=table_start+i*56;
            let kind=le32(bytes,at)?;
            let flags=le32(bytes,at+4)?;
            let off=le64(bytes,at+8)?;
            let va=le64(bytes,at+16)?;
            let file=le64(bytes,at+32)?;
            let mem=le64(bytes,at+40)?;
            let align=le64(bytes,at+48)?;
            match kind {
                PT_NULL=>(),
                PT_LOAD=>{
                    if count==MAX_HEADERS || mem==0 || file>mem
                        || flags&!(PF_R|PF_W|PF_X)!=0
                        || flags&PF_R==0
                        || flags&(PF_W|PF_X)==(PF_W|PF_X)
                        || align!=PAGE_BYTES
                        || va%PAGE_BYTES!=off%PAGE_BYTES
                        || !within(off,file,0,bytes.len() as u64)
                        || range_end(va,mem).is_err()
                    {return Err(Error::Invalid);}
                    let page_start=va/PAGE_BYTES;
                    let page_end=range_end(va,mem)?.div_ceil(PAGE_BYTES);
                    for other in loads[..count].iter().flatten() {
                        let a=other.virtual_address/PAGE_BYTES;
                        let b=range_end(other.virtual_address,other.memory_bytes)?
                            .div_ceil(PAGE_BYTES);
                        // No ambiguous page permissions or writable alias.
                        if page_start<b && a<page_end {
                            return Err(Error::Denied);
                        }
                    }
                    loads[count]=Some(LoadSegment{
                        virtual_address:va,file_offset:off,file_bytes:file,
                        memory_bytes:mem,flags,
                    });
                    count+=1;
                }
                PT_PHDR=>{
                    if phdr.is_some() || file==0
                        || off!=ph_off || file!=ph_num as u64*56
                        || range_end(va,mem).is_err()
                    {return Err(Error::Invalid);}
                    phdr=Some((va,file));
                }
                PT_GNU_STACK=>{
                    if stack_seen || flags&PF_X!=0{return Err(Error::Denied);}
                    stack_seen=true;
                }
                PT_GNU_RELRO=>{
                    if relro.is_some() || mem==0 || range_end(va,mem).is_err(){
                        return Err(Error::Invalid);
                    }
                    relro=Some((va,mem));
                }
                PT_NOTE=>{
                    if flags&(PF_W|PF_X)!=0 || !within(off,file,0,bytes.len() as u64)
                        || file>64*1024
                    {return Err(Error::Invalid);}
                }
                // PT_DYNAMIC, PT_INTERP and unknown loaders are not supported.
                _=>return Err(Error::Denied),
            }
        }
        if count==0{return Err(Error::Invalid);}
        let entry_ok=loads[..count].iter().flatten().any(|seg|
            seg.executable() && seg.contains_file(entry,4)
        );
        if !entry_ok{return Err(Error::Denied);}
        if let Some((start,len))=relro {
            if !loads[..count].iter().flatten()
                .any(|seg|seg.writable()&&seg.contains_memory(start,len))
            {return Err(Error::Denied);}
        }
        if let Some((start,len))=phdr {
            if !loads[..count].iter().flatten()
                .any(|seg|seg.contains_file(start,len))
            {return Err(Error::Denied);}
        }
        Ok(Self{
            verified_bytes:bytes,entry,loads,load_count:count,relro,
            has_executable_stack:false,
        })
    }

    /// Validate all independently signed RELATIVE relocation sidecars before
    /// the caller modifies unpublished RW mappings. Relocations to RX, BSS
    /// values outside the sandbox or duplicate offsets fail as a whole.
    pub fn validate_relative_sidecar(
        &self,
        entries:&[RelativeRelocation],
        randomized_base:u64,
        el0_start:u64,
        el0_end:u64,
    )->Result<(),Error>{
        if randomized_base%PAGE_BYTES!=0
            || el0_start>=el0_end || entries.len()>MAX_RELOCATIONS
        {return Err(Error::Invalid);}
        for seg in self.loads[..self.load_count].iter().flatten() {
            let mapped=randomized_base.checked_add(seg.virtual_address)
                .ok_or(Error::Invalid)?;
            if !within(mapped,seg.memory_bytes,el0_start,el0_end) {
                return Err(Error::Denied);
            }
        }
        for (i,entry) in entries.iter().enumerate(){
            if entry.info>>32!=0 || entry.info&0xffff_ffff!=R_AARCH64_RELATIVE
                || entry.offset%8!=0
            {return Err(Error::Denied);}
            for old in &entries[..i] {
                if old.offset==entry.offset{return Err(Error::Denied);}
            }
            if !self.loads[..self.load_count].iter().flatten()
                .any(|seg|seg.writable()&&seg.contains_memory(entry.offset,8))
            {return Err(Error::Denied);}
            let target=randomized_base.checked_add(entry.offset)
                .ok_or(Error::Invalid)?;
            if !within(target,8,el0_start,el0_end){return Err(Error::Denied);}
            let value=(randomized_base as i128)+(entry.addend as i128);
            if value<el0_start as i128 || value>=el0_end as i128 {
                return Err(Error::Denied);
            }
            let value=value as u64;
            if !self.loads[..self.load_count].iter().flatten().any(|seg|
                randomized_base.checked_add(seg.virtual_address)
                    .is_some_and(|mapped|within(
                        value,1,mapped,mapped.saturating_add(seg.memory_bytes)
                    ))
            ) {return Err(Error::Denied);}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    fn elf()->std::vec::Vec<u8>{
        // One 4KiB RX LOAD followed by a 4KiB RW LOAD.
        let mut b=vec![0u8;0x3000];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4]=2;b[5]=1;b[6]=1;
        b[16..18].copy_from_slice(&TYPE_DYN.to_le_bytes());
        b[18..20].copy_from_slice(&MACHINE_AARCH64.to_le_bytes());
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[52..54].copy_from_slice(&64u16.to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&2u16.to_le_bytes());
        for (i,flag) in [(0,5u32),(1,6u32)] {
            let at=64+i*56;
            b[at..at+4].copy_from_slice(&PT_LOAD.to_le_bytes());
            b[at+4..at+8].copy_from_slice(&flag.to_le_bytes());
            let offset=((i+1)*0x1000) as u64;
            b[at+8..at+16].copy_from_slice(&offset.to_le_bytes());
            b[at+16..at+24].copy_from_slice(&offset.to_le_bytes());
            b[at+32..at+40].copy_from_slice(&0x1000u64.to_le_bytes());
            b[at+40..at+48].copy_from_slice(&0x1000u64.to_le_bytes());
            b[at+48..at+56].copy_from_slice(&PAGE_BYTES.to_le_bytes());
        }
        b[0x1000..0x1004].copy_from_slice(&[0x1f,0x20,0x03,0xd5]); // NOP
        b
    }
    fn parse(b:&[u8])->Result<PieImage<'_>,Error>{
        let hash:[u8;32]=Sha256::digest(b).into();
        PieImage::parse_verified(b,hash)
    }
    #[test]
    fn verified_et_dyn_has_exact_rx_entry_and_private_writable_relocations(){
        let b=elf();
        let image=parse(&b).unwrap();
        assert_eq!(image.entry,0x1000);
        assert_eq!(image.load_count,2);
        let reloc=[RelativeRelocation{
            offset:0x2000,info:R_AARCH64_RELATIVE,addend:0x1000,
        }];
        assert!(image.validate_relative_sidecar(
            &reloc,0x4000_0000,0x4000_0000,0x5000_0000
        ).is_ok());
        let mut bad=reloc;
        bad[0].offset=0x1000; // RX is immutable
        assert!(image.validate_relative_sidecar(
            &bad,0x4000_0000,0x4000_0000,0x5000_0000
        ).is_err());
        bad=reloc;bad[0].info=1;
        assert!(image.validate_relative_sidecar(
            &bad,0x4000_0000,0x4000_0000,0x5000_0000
        ).is_err());
        assert!(image.validate_relative_sidecar(
            &[reloc[0],reloc[0]],0x4000_0000,0x4000_0000,0x5000_0000
        ).is_err());
    }
    #[test]
    fn legacy_exec_wrong_machine_dynamic_loader_and_wx_rejected(){
        let mut b=elf();
        b[16..18].copy_from_slice(&2u16.to_le_bytes());
        assert!(parse(&b).is_err());
        b=elf();b[18..20].copy_from_slice(&62u16.to_le_bytes());
        assert!(parse(&b).is_err());
        b=elf();b[64..68].copy_from_slice(&3u32.to_le_bytes()); // INTERP
        assert!(parse(&b).is_err());
        b=elf();b[64..68].copy_from_slice(&2u32.to_le_bytes()); // DYNAMIC
        assert!(parse(&b).is_err());
        b=elf();b[64+4..64+8].copy_from_slice(&7u32.to_le_bytes());
        assert!(parse(&b).is_err());
        b=elf();b[24..32].copy_from_slice(&0x4000u64.to_le_bytes());
        assert!(parse(&b).is_err());
    }
    #[test]
    fn phdr_overflow_truncated_file_overlap_and_bad_manifest_rejected(){
        let b=elf();
        assert!(PieImage::parse_verified(&b,[1;32]).is_err());
        assert!(parse(&b[..0x1800]).is_err());
        let mut bad=b.clone();
        bad[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse(&bad).is_err());
        bad=b.clone();
        bad[64+56+16..64+56+24].copy_from_slice(&0x1000u64.to_le_bytes());
        assert!(parse(&bad).is_err()); // overlapping LOAD page
        bad=b;
        bad[64+32..64+40].copy_from_slice(&0x2000u64.to_le_bytes());
        assert!(parse(&bad).is_err()); // p_filesz>p_memsz
    }
}
