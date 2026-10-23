//! Linux dirent64 encoding over bounded RAM nodes and read-only boot files.
use super::*;

impl Process<'_> {
    pub fn getdents(
        &mut self,
        fs: &FileSystem,
        fd: i32,
        assets: &[(&str, &[u8])],
        out: &mut [u8],
    ) -> Result<usize, Errno> {
        let path = self.directory_path(fs, fd)?;
        let slot = self.description(fd)?;
        let description = self.objects.get(slot)?;
        let mut cookie = usize::try_from(description.offset).map_err(|_| Errno::Inval)?;
        let limit = 2 + cyxia_ai_fs::NODES + assets.len();
        let mut written = 0;
        while cookie < limit {
            let candidate = if cookie < 2 {
                Some((
                    if cookie == 0 { "." } else { ".." },
                    fs.identity(if cookie == 0 { path } else { path.parent() })?,
                    4,
                ))
            } else if cookie < 2 + cyxia_ai_fs::NODES {
                // Paths below are owned values; emit the record in this branch.
                if let Some(entry) = fs.directory_entry(path, cookie - 2)
                    && !assets.iter().any(|(name, _)| *name == entry.path.as_str())
                    && !emit(
                        out,
                        &mut written,
                        cookie + 1,
                        entry.path.name(),
                        fs.identity(entry.path)?,
                        if entry.kind == Kind::Directory { 4 } else { 8 },
                    )?
                {
                    break;
                }
                cookie += 1;
                continue;
            } else {
                let (name, _) = assets[cookie - 2 - cyxia_ai_fs::NODES];
                let asset = Path::resolve(Path::ROOT, name)?;
                if asset.parent() != path {
                    cookie += 1;
                    continue;
                }
                // name is borrowed from the immutable boot table.
                Some((
                    name.rsplit('/').next().ok_or(Errno::Io)?,
                    0x10000 + (cookie - 2 - cyxia_ai_fs::NODES) as u64,
                    8,
                ))
            };
            if let Some((name, inode, kind)) = candidate
                && !emit(out, &mut written, cookie + 1, name, inode, kind)?
            {
                break;
            }
            cookie += 1;
        }
        self.objects.update(
            slot,
            Description {
                offset: cookie as u64,
                ..description
            },
        )?;
        Ok(written)
    }
}

fn emit(
    out: &mut [u8],
    written: &mut usize,
    next: usize,
    name: &str,
    inode: u64,
    kind: u8,
) -> Result<bool, Errno> {
    let size = (19 + name.len() + 1).next_multiple_of(8);
    if size > out.len() - *written {
        return if *written == 0 {
            Err(Errno::Inval)
        } else {
            Ok(false)
        };
    }
    let record = &mut out[*written..*written + size];
    record.fill(0);
    record[..8].copy_from_slice(&inode.to_le_bytes());
    record[8..16].copy_from_slice(&(next as u64).to_le_bytes());
    record[16..18].copy_from_slice(&(size as u16).to_le_bytes());
    record[18] = kind;
    record[19..19 + name.len()].copy_from_slice(name.as_bytes());
    *written += size;
    Ok(true)
}
