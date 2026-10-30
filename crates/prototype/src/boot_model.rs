//! Boot self-test for the exact untrained seed currently embedded by ABI3.
//! Full intermediate integer traces are frozen by an independent reference.
//! Passing these vectors is NOT trained-model provenance or A16 acceptance.
use crate::model::Model;

pub const PARAMETER_HASH: [u8; 32] = [
    155, 155, 248, 122, 150, 157, 123, 12, 107, 227, 169, 234, 5, 100, 113, 77, 135, 207, 18, 241,
    87, 128, 55, 134, 125, 148, 92, 33, 12, 95, 12, 163,
];
pub const CASES: usize = 4;
pub const OUTPUT_MAGIC: u64 = 0x4359_584d_5445_5354;
const EXPECTED: [[i16; 49]; CASES] = [
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
    [
        256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 320, 320, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
        256, 256, 256, 320, 320, 378,
    ],
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
    [
        32767, 0, 32767, 0, 32767, 0, 32767, 0, 32767, 0, 32767, 0, 0, 32767, 32735, 32735, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32767, 0, 32767, 0, 32767, 0, 32767, 0, 32767, 0,
        32767, 0, 0, 32767, 32735, 32735, 12287,
    ],
];

pub fn check(bytes: &[u8]) -> bool {
    let Ok(model) = Model::parse(bytes) else {
        return false;
    };
    for (case, expected) in EXPECTED.iter().enumerate() {
        let input = core::array::from_fn(|i| match case {
            0 => 0,
            1 => 256,
            2 => i16::MIN,
            _ => {
                if i % 2 == 0 {
                    i16::MAX
                } else {
                    -129
                }
            }
        });
        let trace = model.trace(&input);
        if trace.hidden1 != expected[..32]
            || trace.hidden2 != expected[32..48]
            || trace.output != expected[48]
        {
            return false;
        }
    }
    true
}
