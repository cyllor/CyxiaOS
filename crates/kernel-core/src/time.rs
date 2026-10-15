use cyxia_contracts::TimeNs;
#[derive(Debug,Clone,Copy,PartialEq,Eq)] pub enum ClockError{Invalid,Overflow}
pub fn ticks_to_ns(ticks:u64,freq:u64)->Result<TimeNs,ClockError>{if freq==0{return Err(ClockError::Invalid)}let n=(ticks as u128)*1_000_000_000/(freq as u128);u64::try_from(n).map(TimeNs).map_err(|_|ClockError::Overflow)}
pub fn next_deadline(previous:u64,period:u64,now:u64)->Result<u64,ClockError>{if period==0{return Err(ClockError::Invalid)}let next=previous.checked_add(period).ok_or(ClockError::Overflow)?;if next>now{Ok(next)}else{now.checked_add(period).ok_or(ClockError::Overflow)}}
