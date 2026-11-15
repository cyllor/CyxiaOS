use cyxia_platform_pc::rtc::{Cmos, Error, read_seconds};

struct Clock { bytes: [u8; 128], updating: bool, rollover: bool, samples: usize }
impl Clock {
    fn new() -> Self {
        let mut bytes = [0; 128];
        bytes[0] = 0x56; bytes[2] = 0x34; bytes[4] = 0x12;
        bytes[7] = 0x29; bytes[8] = 0x02; bytes[9] = 0x24; bytes[0x32] = 0x20;
        bytes[10] = 0x26; bytes[11] = 2; bytes[13] = 0x80;
        Self { bytes, updating: false, rollover: false, samples: 0 }
    }
}
impl Cmos for Clock {
    fn read(&mut self, register: u8) -> u8 {
        if register == 10 && self.updating { return 0xa6; }
        if register == 0 {
            self.samples += 1;
            if self.rollover && self.samples == 2 { self.bytes[0] += 1; }
        }
        self.bytes[usize::from(register)]
    }
}

#[test]
fn bcd_binary_and_twelve_hour_clocks_agree() {
    let mut clock = Clock::new();
    let expected = 1_709_210_096; // 2024-02-29 12:34:56 UTC
    assert_eq!(read_seconds(&mut clock, 0x32), Ok(expected));
    clock.bytes[11] = 0; clock.bytes[4] = 0x92; // noon, BCD 12-hour
    assert_eq!(read_seconds(&mut clock, 0x32), Ok(expected));
    clock.bytes[11] = 6; clock.bytes[0] = 56; clock.bytes[2] = 34;
    clock.bytes[4] = 12; clock.bytes[7] = 29; clock.bytes[8] = 2;
    clock.bytes[9] = 24; clock.bytes[0x32] = 20;
    assert_eq!(read_seconds(&mut clock, 0x32), Ok(expected));
    clock.bytes[11] = 4; clock.bytes[4] = 12; // midnight, binary 12-hour
    assert_eq!(read_seconds(&mut clock, 0x32), Ok(expected - 43_200));
}

#[test]
fn update_and_rollover_never_publish_torn_time() {
    let mut clock = Clock::new(); clock.updating = true;
    assert_eq!(read_seconds(&mut clock, 0x32), Err(Error::Busy));
    clock.updating = false; clock.rollover = true;
    assert_eq!(read_seconds(&mut clock, 0x32), Ok(1_709_210_097));
    assert!(clock.samples >= 4);
}

#[test]
fn invalid_battery_calendar_encoding_or_missing_century_fail() {
    for (index, value) in [(13, 0), (0, 0x5a), (7, 0x30), (8, 0),
                           (9, 0x23), (0x32, 0), (11, 0x82), (10, 0x66)] {
        let mut clock = Clock::new(); clock.bytes[index] = value;
        assert!(read_seconds(&mut clock, 0x32).is_err(), "register {index}");
    }
    let mut clock = Clock::new();
    assert_eq!(read_seconds(&mut clock, 0), Err(Error::Invalid));
}

#[test]
fn gregorian_century_rules_and_unix_epoch() {
    let mut clock = Clock::new();
    clock.bytes[9] = 0; clock.bytes[0x32] = 0x21;
    assert_eq!(read_seconds(&mut clock, 0x32), Err(Error::Invalid)); // 2100 not leap
    clock.bytes[0x32] = 0x20;
    assert!(read_seconds(&mut clock, 0x32).is_ok()); // 2000 leap
    clock.bytes[0] = 0; clock.bytes[2] = 0; clock.bytes[4] = 0;
    clock.bytes[7] = 1; clock.bytes[8] = 1; clock.bytes[9] = 0x70;
    clock.bytes[0x32] = 0x19;
    assert_eq!(read_seconds(&mut clock, 0x32), Ok(0));
}
