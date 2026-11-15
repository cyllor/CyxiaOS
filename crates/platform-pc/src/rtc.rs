//! Read-only MC146818 clock; register contract matches QEMU 10.2's
//! hw/rtc/mc146818rtc.c. The board supplies its actual century register.
//! No guessed century, timestamp, or fallback clock is returned.

pub trait Cmos { fn read(&mut self, register: u8) -> u8; }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { Busy, Invalid, Unavailable }

#[derive(Clone, Copy, PartialEq, Eq)]
struct Snapshot { calendar: [u8; 7], mode: u8 }
fn snapshot(cmos: &mut impl Cmos, century: u8) -> Result<Snapshot, Error> {
    if cmos.read(13) & 0x80 == 0 { return Err(Error::Unavailable); }
    let control = cmos.read(10);
    if control & 0x70 != 0x20 { return Err(Error::Unavailable); }
    if control & 0x80 != 0 { return Err(Error::Busy); }
    let mode = cmos.read(11);
    if mode & 0x80 != 0 { return Err(Error::Busy); }
    let calendar = [0, 2, 4, 7, 8, 9, century].map(|register| cmos.read(register));
    if cmos.read(10) & 0x80 != 0 || cmos.read(11) != mode { return Err(Error::Busy); }
    Ok(Snapshot { calendar, mode })
}

pub fn read_seconds(cmos: &mut impl Cmos, century: u8) -> Result<u64, Error> {
    if !(14..128).contains(&century) { return Err(Error::Invalid); }
    // Double sampling rejects a rollover even when UIP changed between reads.
    // A bounded attempt count also handles a stopped or malicious device.
    for _ in 0..16 {
        let first = match snapshot(cmos, century) {
            Err(Error::Busy) => continue, other => other?,
        };
        let second = match snapshot(cmos, century) {
            Err(Error::Busy) => continue, other => other?,
        };
        if first == second { return decode(first); }
    }
    Err(Error::Busy)
}
fn leap(year: u64) -> bool { year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) }
fn decode(value: Snapshot) -> Result<u64, Error> {
    let binary = value.mode & 4 != 0;
    let number = |n: u8| -> Result<u64, Error> {
        if binary { return Ok(u64::from(n)); }
        if n & 15 > 9 || n >> 4 > 9 { return Err(Error::Invalid); }
        Ok(u64::from(n >> 4) * 10 + u64::from(n & 15))
    };
    let [sec, min, hour, day, month, year, century] = value.calendar;
    let (sec, min, day, month) = (number(sec)?, number(min)?, number(day)?, number(month)?);
    let hour = if value.mode & 2 != 0 {
        number(hour)?
    } else {
        let h = number(hour & 0x7f)?;
        if !(1..=12).contains(&h) { return Err(Error::Invalid); }
        h % 12 + if hour & 0x80 != 0 { 12 } else { 0 }
    };
    let (year, century) = (number(year)?, number(century)?);
    if year > 99 || century > 99 { return Err(Error::Invalid); }
    let year = century * 100 + year;
    if !(1970..=9999).contains(&year) || sec > 59 || min > 59 || hour > 23 || !(1..=12).contains(&month) {
        return Err(Error::Invalid);
    }
    let days_in_month = [31, if leap(year) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if day == 0 || day > days_in_month[month as usize - 1] { return Err(Error::Invalid); }
    let leaps_before = |y: u64| (y - 1) / 4 - (y - 1) / 100 + (y - 1) / 400;
    let days = (year - 1970) * 365 + leaps_before(year) - leaps_before(1970)
        + days_in_month[..month as usize - 1].iter().sum::<u64>() + day - 1;
    Ok(days * 86_400 + hour * 3600 + min * 60 + sec)
}
