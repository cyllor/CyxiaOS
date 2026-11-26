//! 16550 receive semantics shared by the port adapter and host fault tests.
use cyxia_contracts::PlatformError;
pub trait Registers {
    fn read_register(&mut self, offset: u16) -> u8;
}

pub fn receive(registers: &mut impl Registers) -> Result<Option<u8>, PlatformError> {
    let status = registers.read_register(5);
    let byte = (status & 1 != 0).then(|| registers.read_register(0));
    // LSR: overrun/parity/framing/break and FIFO error summary. Drain a present
    // damaged byte, but never expose it as ordinary command input. The consumer
    // poisons the whole line through its next terminator, including buffered tail.
    if status & 0x9e != 0 {
        return Err(PlatformError::Invalid);
    }
    Ok(byte)
}
