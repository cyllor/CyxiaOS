//! Finite IEEE 754 binary64 operations using integers only. Every primitive
//! rounds independently to nearest, ties to even; there is no fused operation.
//! Subnormals and signed zero are preserved. Nonfinite values are rejected.
use core::cmp::Ordering;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloatError {
    NonFinite,
    DivisionByZero,
    Overflow,
    Range,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct F64(u64);
const SIGN: u64 = 1 << 63;
const FRACTION: u64 = (1 << 52) - 1;
impl F64 {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(0x3ff0_0000_0000_0000);
    pub const HALF: Self = Self(0x3fe0_0000_0000_0000);
    pub const fn from_bits_checked(bits: u64) -> Result<Self, FloatError> {
        if (bits >> 52) & 0x7ff == 0x7ff {
            Err(FloatError::NonFinite)
        } else {
            Ok(Self(bits))
        }
    }
    pub const fn to_bits(self) -> u64 {
        self.0
    }
    pub const fn abs(self) -> Self {
        Self(self.0 & !SIGN)
    }
    pub const fn neg(self) -> Self {
        Self(self.0 ^ SIGN)
    }
    pub const fn is_zero(self) -> bool {
        self.0 & !SIGN == 0
    }
    pub const fn negative(self) -> bool {
        self.0 & SIGN != 0
    }
    pub fn compare(self, other: Self) -> Ordering {
        if self.is_zero() && other.is_zero() {
            return Ordering::Equal;
        }
        match (self.negative(), other.negative()) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => self.0.cmp(&other.0),
            (true, true) => other.0.cmp(&self.0),
        }
    }
    pub fn clamp(self, low: Self, high: Self) -> Result<Self, FloatError> {
        if low.compare(high) == Ordering::Greater {
            return Err(FloatError::Range);
        }
        Ok(if self.compare(low) == Ordering::Less {
            low
        } else if self.compare(high) == Ordering::Greater {
            high
        } else {
            self
        })
    }
    /// Integer significand and binary exponent: value = sign * mantissa * 2^e.
    fn decode(self) -> (bool, u64, i32) {
        let field = ((self.0 >> 52) & 0x7ff) as i32;
        if field == 0 {
            (self.negative(), self.0 & FRACTION, -1074)
        } else {
            (
                self.negative(),
                (1 << 52) | (self.0 & FRACTION),
                field - 1075,
            )
        }
    }
    fn normalized(self) -> (bool, u64, i32) {
        let (sign, m, e) = self.decode();
        if m == 0 {
            return (sign, m, e);
        }
        let shift = m.leading_zeros() - 11;
        (sign, m << shift, e - shift as i32)
    }
    fn jam(value: u128, shift: u32) -> u128 {
        if shift == 0 {
            value
        } else if shift >= 128 {
            u128::from(value != 0)
        } else {
            (value >> shift) | u128::from(value & ((1u128 << shift) - 1) != 0)
        }
    }
    fn round_right(value: u128, shift: u32) -> u128 {
        if shift == 0 {
            return value;
        }
        if shift > 128 {
            return 0;
        }
        if shift == 128 {
            return u128::from(value > (1u128 << 127));
        }
        let q = value >> shift;
        let tail = value & ((1u128 << shift) - 1);
        let half = 1u128 << (shift - 1);
        q + u128::from(tail > half || (tail == half && q & 1 != 0))
    }
    fn pack(sign: bool, mantissa: u128, exponent: i32) -> Result<Self, FloatError> {
        let sign = if sign { SIGN } else { 0 };
        if mantissa == 0 {
            return Ok(Self(sign));
        }
        let bits = 128 - mantissa.leading_zeros() as i32;
        let mut high = exponent + bits - 1;
        if high > 1023 {
            return Err(FloatError::Overflow);
        }
        // Select the final binary64 lattice before rounding. In particular,
        // an underflowing product/quotient must not first round to a normal
        // significand and then round again to the subnormal lattice.
        let target = if high >= -1022 { high - 52 } else { -1074 };
        let shift = target - exponent;
        let mut rounded = if shift >= 0 {
            Self::round_right(mantissa, shift as u32)
        } else {
            mantissa << (-shift as u32)
        };
        if rounded == 0 {
            return Ok(Self(sign));
        }
        if high < -1022 {
            // Rounding can carry the largest subnormal into the first normal.
            return Ok(Self(sign | rounded as u64));
        }
        if rounded >= 1u128 << 53 {
            rounded >>= 1;
            high += 1;
            if high > 1023 {
                return Err(FloatError::Overflow);
            }
        }
        Ok(Self(
            sign | (((high + 1023) as u64) << 52) | (rounded as u64 & FRACTION),
        ))
    }
    pub fn from_u64(value: u64) -> Self {
        Self::pack(false, u128::from(value), 0)
            .expect("u64 always has a finite binary64 representation")
    }
    pub fn from_i64(value: i64) -> Self {
        Self::pack(value < 0, u128::from(value.unsigned_abs()), 0)
            .expect("i64 always has a finite binary64 representation")
    }
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: Self) -> Result<Self, FloatError> {
        if self.is_zero() && other.is_zero() {
            return Ok(Self(self.0 & other.0 & SIGN));
        }
        if self.is_zero() {
            return Ok(other);
        }
        if other.is_zero() {
            return Ok(self);
        }
        let (sa, a, ea) = self.normalized();
        let (sb, b, eb) = other.normalized();
        let e = ea.max(eb);
        // Three low bits retain guard, round, and sticky information. Severe
        // cancellation requires neighboring exponents, where these shifts
        // discard no significand bits. More distant operands cannot cancel
        // enough leading bits to promote the sticky approximation to data.
        let a = Self::jam(u128::from(a) << 3, (e - ea) as u32);
        let b = Self::jam(u128::from(b) << 3, (e - eb) as u32);
        if sa == sb {
            Self::pack(sa, a + b, e - 3)
        } else if a >= b {
            Self::pack(if a == b { false } else { sa }, a - b, e - 3)
        } else {
            Self::pack(sb, b - a, e - 3)
        }
    }
    #[allow(clippy::should_implement_trait)]
    pub fn sub(self, other: Self) -> Result<Self, FloatError> {
        self.add(other.neg())
    }
    #[allow(clippy::should_implement_trait)]
    pub fn mul(self, other: Self) -> Result<Self, FloatError> {
        let (sa, a, ea) = self.decode();
        let (sb, b, eb) = other.decode();
        Self::pack(sa ^ sb, u128::from(a) * u128::from(b), ea + eb)
    }
    #[allow(clippy::should_implement_trait)]
    pub fn div(self, other: Self) -> Result<Self, FloatError> {
        if other.is_zero() {
            return Err(FloatError::DivisionByZero);
        }
        if self.is_zero() {
            return Ok(Self(if self.negative() ^ other.negative() {
                SIGN
            } else {
                0
            }));
        }
        let (sa, a, ea) = self.normalized();
        let (sb, b, eb) = other.normalized();
        let numerator = u128::from(a) << 63;
        let divisor = u128::from(b);
        let q = numerator / divisor;
        let remainder = numerator % divisor;
        // The quotient has at least 63 significant bits; a binary64 result
        // discards at least ten. Jam the nonzero remainder below all retained
        // bits so exact halfway results remain distinguishable from above.
        Self::pack(sa ^ sb, q | u128::from(remainder != 0), ea - eb - 63)
    }
    fn truncated_magnitude(self) -> Result<u128, FloatError> {
        let (_, m, e) = self.decode();
        if e >= 0 {
            if e > 74 {
                return Err(FloatError::Range);
            }
            Ok(u128::from(m) << e)
        } else if e <= -128 {
            Ok(0)
        } else {
            Ok(u128::from(m) >> -e)
        }
    }
    pub fn to_i64_trunc(self) -> Result<i64, FloatError> {
        let value = self.truncated_magnitude()?;
        if self.negative() {
            if value > 1u128 << 63 {
                return Err(FloatError::Range);
            }
            Ok((-(value as i128)) as i64)
        } else {
            i64::try_from(value).map_err(|_| FloatError::Range)
        }
    }
    pub fn to_u64_trunc(self) -> Result<u64, FloatError> {
        let value = self.truncated_magnitude()?;
        if self.negative() && value != 0 {
            return Err(FloatError::Range);
        }
        u64::try_from(value).map_err(|_| FloatError::Range)
    }
    pub fn floor(self) -> Result<Self, FloatError> {
        let (_, m, e) = self.decode();
        if e >= 0 || m == 0 {
            return Ok(self);
        }
        let fractional = if e <= -64 {
            true
        } else {
            m & ((1u64 << -e) - 1) != 0
        };
        let truncated = self.to_i64_trunc()?;
        Ok(Self::from_i64(if self.negative() && fractional {
            truncated.checked_sub(1).ok_or(FloatError::Range)?
        } else {
            truncated
        }))
    }
}
