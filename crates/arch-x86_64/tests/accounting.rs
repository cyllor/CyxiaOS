// This test target deliberately exercises the architecture-neutral stamp/ABI
// contract on the host; RDMSR is only compiled for the bare-metal target.
use cyxia_arch_x86_64::accounting::*;

#[test]
fn capability_is_exact_and_fail_closed() {
    assert!(Capability::from_cpuid(CAPABILITY_WORDS).is_ok());
    for word in 0..4 {
        let mut words = CAPABILITY_WORDS;
        words[word] ^= 1;
        assert_eq!(Capability::from_cpuid(words), Err(ClockError::Capability));
    }
    assert_eq!(Capability::from_cpuid([0; 4]), Err(ClockError::Capability));
}

#[test]
fn debit_requires_same_cpu_source_and_monotonic_execution() {
    let start = ExecutionStamp {
        cpu: 2,
        source: SOURCE_ABI,
        ns: 100,
    };
    assert_eq!(
        elapsed_ns(start, ExecutionStamp { ns: 109, ..start }),
        Ok(9)
    );
    assert_eq!(elapsed_ns(start, start), Ok(0));
    assert_eq!(
        elapsed_ns(start, ExecutionStamp { cpu: 3, ..start }),
        Err(ClockError::Cpu)
    );
    assert_eq!(
        elapsed_ns(start, ExecutionStamp { source: 2, ..start }),
        Err(ClockError::Source)
    );
    assert_eq!(
        elapsed_ns(start, ExecutionStamp { ns: 99, ..start }),
        Err(ClockError::Regression)
    );
    assert_eq!(
        elapsed_ns(
            ExecutionStamp { source: 0, ..start },
            ExecutionStamp { source: 0, ..start }
        ),
        Err(ClockError::Source)
    );
}

#[test]
fn accumulation_never_saturates_or_wraps() {
    assert_eq!(add_debit_ns(u64::MAX - 1, 1), Ok(u64::MAX));
    assert_eq!(add_debit_ns(u64::MAX, 1), Err(ClockError::Overflow));
}

#[test]
fn monotonic_deadline_is_a_distinct_clock_type() {
    let now = MonotonicStamp {
        source: SOURCE_ABI,
        ns: 20,
    };
    assert_eq!(
        now.deadline_after(30),
        Ok(MonotonicStamp {
            source: SOURCE_ABI,
            ns: 50
        })
    );
    assert_eq!(now.deadline_after(u64::MAX), Err(ClockError::Overflow));
    assert_eq!(
        MonotonicStamp { source: 0, ns: 20 }.deadline_after(1),
        Err(ClockError::Source)
    );
}
