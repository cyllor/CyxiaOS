use cyxia_posix::ImageAbi;
use cyxia_posix::linux_abi::{self, Call};
#[test]
fn inotify_uses_isa_numbers_and_legacy_init_has_no_flags() {
    for (abi, numbers) in [
        (ImageAbi::X86_64, [294, 254, 255]),
        (ImageAbi::Aarch64, [26, 27, 28]),
    ] {
        for (number, call) in numbers.into_iter().zip([
            Call::InotifyInit1,
            Call::InotifyAddWatch,
            Call::InotifyRmWatch,
        ]) {
            let args = [7, 8, 9, 0, 0, 0];
            let invocation = linux_abi::decode(abi, number, args).unwrap();
            assert_eq!(invocation.call, call);
            assert_eq!(invocation.args, args);
        }
    }
    let legacy = linux_abi::decode(ImageAbi::X86_64, 253, [u64::MAX; 6]).unwrap();
    assert_eq!(legacy.call, Call::InotifyInit1);
    assert_eq!(legacy.args[0], 0);
}
#[test]
fn flock_uses_each_linux_isa_number_and_preserves_descriptor_and_operation() {
    for (abi, number) in [(ImageAbi::X86_64, 73), (ImageAbi::Aarch64, 32)] {
        let args = [7, 2 | 4, 0, 0, 0, 0];
        let invocation = linux_abi::decode(abi, number, args).unwrap();
        assert_eq!(invocation.call, Call::Flock);
        assert_eq!(invocation.args, args);
    }
    assert_eq!(
        linux_abi::decode(ImageAbi::X86_64, 32, [0; 6])
            .unwrap()
            .call,
        Call::Dup
    );
    assert_eq!(
        linux_abi::decode(ImageAbi::Aarch64, 73, [0; 6])
            .unwrap()
            .call,
        Call::Ppoll
    );
}
#[test]
fn x86_linux_numbers_and_clone_arguments_are_not_arm_or_native_numbers() {
    assert_eq!(
        linux_abi::decode(ImageAbi::X86_64, 0, [0; 6]).unwrap().call,
        Call::Read
    );
    assert_eq!(
        linux_abi::decode(ImageAbi::X86_64, 1, [0; 6]).unwrap().call,
        Call::Write
    );
    assert_eq!(
        linux_abi::decode(ImageAbi::Aarch64, 63, [0; 6])
            .unwrap()
            .call,
        Call::Read
    );
    assert_eq!(
        linux_abi::decode(ImageAbi::X86_64, 56, [1, 2, 3, 4, 5, 6])
            .unwrap()
            .args,
        [1, 2, 3, 5, 4, 6]
    );
    let open = linux_abi::decode(ImageAbi::X86_64, 2, [11, 22, 33, 0, 0, 0]).unwrap();
    assert_eq!(open.call, Call::Openat);
    assert_eq!(open.args[..4], [(-100i64) as u64, 11, 22, 33]);
}
#[test]
fn x86_stat_layout_is_144_bytes_with_64_bit_nlink() {
    let info = cyxia_posix::FileInfo {
        inode: 7,
        size: 12345,
        mode: 0o100644,
        links: 3,
    };
    let bytes = linux_abi::stat_x86_64(info);
    assert_eq!(bytes.len(), 144);
    assert_eq!(&bytes[16..24], &3u64.to_le_bytes());
    assert_eq!(&bytes[24..28], &0o100644u32.to_le_bytes());
    assert_eq!(&bytes[48..56], &12345u64.to_le_bytes());
    assert_eq!(&bytes[56..64], &4096u64.to_le_bytes());
}

#[test]
fn x86_flag_and_epoll_wire_layouts_are_separate_from_internal_policy() {
    let internal =
        linux_abi::decode_open_flags(ImageAbi::X86_64, 0x10000 | 0x20000 | 0x8000 | 2).unwrap();
    assert_eq!(
        internal,
        u64::from(cyxia_posix::O_DIRECTORY | cyxia_posix::O_NOFOLLOW | 2)
    );
    assert_eq!(
        linux_abi::encode_open_flags(ImageAbi::X86_64, internal as u32),
        0x10000 | 0x20000 | 2
    );
    assert!(linux_abi::decode_open_flags(ImageAbi::X86_64, 0x4000).is_err());
    assert_eq!(linux_abi::epoll_bytes(ImageAbi::X86_64), 12);
    assert_eq!(linux_abi::epoll_data_offset(ImageAbi::X86_64), 4);
    assert_eq!(linux_abi::epoll_bytes(ImageAbi::Aarch64), 16);
}

#[test]
fn clone_stack_matches_musl_126_argument_word_without_moving_child_sp() {
    // musl v1.2.6 src/thread/x86_64/clone.s: and RSI,-16; sub RSI,8;
    // store argument at [RSI], clone, then child pops one 8-byte RDI argument.
    // ARM src/thread/aarch64/clone.s instead stores/loads two words at aligned SP.
    let x86_sp = 0x0400_0ff8; // One word remains before a potential guard page.
    assert_eq!(
        linux_abi::validate_clone_stack(ImageAbi::X86_64, x86_sp),
        Ok(8)
    );
    assert_eq!(
        linux_abi::validate_clone_stack(ImageAbi::X86_64, x86_sp + 1),
        Ok(8)
    );
    assert!(linux_abi::validate_clone_stack(ImageAbi::Aarch64, x86_sp).is_err());
    assert_eq!(
        linux_abi::validate_clone_stack(ImageAbi::Aarch64, 0x0400_0ff0),
        Ok(16)
    );
    assert!(linux_abi::validate_clone_stack(ImageAbi::X86_64, 0).is_err());
    assert!(linux_abi::validate_clone_stack(ImageAbi::X86_64, 0xffff800000000000).is_err());
}

#[test]
fn legacy_epoll_create_uses_signed_32_bit_size_and_rejects_nonpositive_values() {
    // Linux v6.12 fs/eventpoll.c SYSCALL_DEFINE1(epoll_create, int, size).
    for size in [0, u64::MAX, 0x8000_0000, 0xffff_ffff, 0x1_0000_0000] {
        assert_eq!(
            linux_abi::decode(ImageAbi::X86_64, 213, [size, 0, 0, 0, 0, 0]),
            Err(cyxia_posix::Errno::Inval),
        );
    }
    for size in [1, i32::MAX as u64, 0xffff_ffff_0000_0001] {
        let call = linux_abi::decode(ImageAbi::X86_64, 213, [size, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(call.call, Call::EpollCreate1);
        assert_eq!(call.args[0], 0);
    }
    // Modern epoll_create1 keeps its distinct flags contract on both ISAs.
    assert_eq!(
        linux_abi::decode(ImageAbi::X86_64, 291, [0; 6])
            .unwrap()
            .call,
        Call::EpollCreate1
    );
    assert_eq!(
        linux_abi::decode(ImageAbi::Aarch64, 20, [0; 6])
            .unwrap()
            .call,
        Call::EpollCreate1
    );
}
