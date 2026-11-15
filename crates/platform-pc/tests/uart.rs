use cyxia_contracts::PlatformError;
use cyxia_platform_pc::uart::{Registers, receive};
struct Uart { status: u8, reads: usize }
impl Registers for Uart {
    fn read_register(&mut self, offset: u16) -> u8 {
        match offset {
            5 => self.status,
            0 => { self.reads += 1; b'x' }
            _ => panic!("unexpected UART register"),
        }
    }
}
#[test]
fn idle_does_not_consume_rx_and_valid_input_consumes_once() {
    let mut uart = Uart { status: 0x60, reads: 0 };
    assert_eq!(receive(&mut uart), Ok(None));
    assert_eq!(uart.reads, 0);
    uart.status |= 1;
    assert_eq!(receive(&mut uart), Ok(Some(b'x')));
    assert_eq!(uart.reads, 1);
}
#[test]
fn line_damage_cannot_become_a_truncated_shell_command() {
    for error in [2, 4, 8, 16, 128] {
        for available in [0, 1] {
            let mut uart = Uart { status: 0x60 | error | available, reads: 0 };
            assert_eq!(receive(&mut uart), Err(PlatformError::Invalid));
            assert_eq!(uart.reads, available as usize);
        }
    }
}
