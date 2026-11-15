"""Explicit user-space build targets; names never stand in for ISA validation."""
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import struct


@dataclass(frozen=True)
class TargetProfile:
    architecture: str
    c_target: str
    rust_target: str
    machine: int
    entry_alignment: int
    clang_args: tuple[str, ...]
    linker_emulation: str
    cpu: str

    @property
    def builtins_archive(self):
        return 'libclang_rt.builtins-' + self.architecture + '.a'

    def default_output(self, root):
        return Path(root) / 'artifacts/sysroot' / (self.architecture + '-musl')

    def cc(self, prefix):
        return Path(prefix) / 'bin' / (self.c_target + '-cc')

    def meson_machine(self):
        return ("[host_machine]\nsystem = 'linux'\ncpu_family = " + repr(self.architecture) +
                '\ncpu = ' + repr(self.cpu) + "\nendian = 'little'\n")

    def identity(self):
        return asdict(self)

    def require_report(self, report):
        triple = report.get('target_triple', report.get('target'))
        if (triple not in (self.c_target, self.rust_target) or
                report.get('architecture', self.architecture) != self.architecture):
            raise ValueError('SDK/build report target does not match selected ' + self.architecture)

    def inspect_archive(self, path):
        """Inspect every ELF object, including extended archive member names."""
        path = Path(path)
        data = path.read_bytes()
        if data[:8] != b'!<arch>\n':
            raise ValueError('Not a regular static archive: ' + str(path))
        offset, count = 8, 0
        while offset < len(data):
            header = data[offset:offset + 60]
            if len(header) != 60 or header[58:] != b'`\n':
                raise ValueError('Invalid static archive header: ' + str(path))
            try:
                size = int(header[48:58].strip())
            except ValueError as error:
                raise ValueError('Invalid archive member size') from error
            if size < 0 or offset + 60 + size > len(data):
                raise ValueError('Truncated archive member: ' + str(path))
            body = data[offset + 60:offset + 60 + size]
            name = header[:16].strip()
            if name.startswith(b'#1/'):
                length = int(name[3:])
                if length < 1 or length > len(body):
                    raise ValueError('Invalid extended archive name')
                name, body = body[:length].rstrip(b'\0'), body[length:]
            if name not in (b'/', b'//', b'/SYM64/', b'__.SYMDEF', b'__.SYMDEF SORTED'):
                if (len(body) < 20 or body[:7] != b'\x7fELF\x02\x01\x01' or
                        struct.unpack_from('<HH', body, 16) != (1, self.machine)):
                    raise ValueError('Foreign/non-ELF object in ' + str(path) + ': ' + repr(name))
                count += 1
            offset += 60 + size + size % 2
        if count == 0 or offset != len(data):
            raise ValueError('Empty/truncated static archive: ' + str(path))
        return dict(sha256=hashlib.sha256(data).hexdigest(), bytes=len(data),
                    architecture=self.architecture, machine=self.machine, object_count=count)


_PROFILES = {
    'aarch64': TargetProfile('aarch64', 'aarch64-linux-musl', 'aarch64-unknown-linux-musl',
                             183, 4, ('--target=aarch64-linux-musl', '-march=armv8-a', '-mno-outline-atomics'),
                             'aarch64elf', 'cortex-a53'),
    'x86_64': TargetProfile('x86_64', 'x86_64-linux-musl', 'x86_64-unknown-linux-musl',
                            62, 1, ('--target=x86_64-linux-musl', '-mno-red-zone'),
                            'elf_x86_64', 'x86-64'),
}


def profile_for(target='aarch64'):
    if isinstance(target, TargetProfile):
        if _PROFILES.get(target.architecture) != target:
            raise ValueError('Unregistered target profile')
        return target
    try:
        return _PROFILES[target]
    except (KeyError, TypeError) as error:
        raise ValueError('Unsupported user-space architecture: ' + str(target)) from error


def inspect_link_archive(path, prefix, target='aarch64'):
    """Validate code archives and musl's explicit empty compatibility aliases.

    Musl implements math/pthread/etc in libc itself. Its named compatibility
    archives contain no code, so they have no ISA to infer. Only these exact
    SDK paths may use an empty archive; their receipt binds the selected libc.
    The ordinary archive inspector always requires actual target ELF objects.
    """
    selected = profile_for(target)
    path, prefix = Path(path), Path(prefix).resolve()
    try:
        return selected.inspect_archive(path)
    except ValueError:
        names = {'lib' + name + '.a' for name in ('m', 'rt', 'pthread', 'crypt', 'util', 'xnet', 'resolv', 'dl')}
        # llvm-ar's native BSD empty-symbol-index encoding, or GNU ar's empty
        # archive header. No archive member capable of carrying code is allowed.
        empty_bsd = (b'!<arch>\n#1/12           0           0     0     0       20        `\n'
                     b'__.SYMDEF' + bytes(11))
        if (path.name not in names or path.is_symlink()
                or path.resolve() != prefix / 'sysroot/usr/lib' / path.name
                or path.read_bytes() not in (b'!<arch>\n', empty_bsd)):
            raise
        report = json.loads((prefix / 'build-report.json').read_text())
        selected.require_report(report)
        libc = selected.inspect_archive(prefix / 'sysroot/usr/lib/libc.a')
        if libc['sha256'] != report['libc_sha256']:
            raise ValueError('Musl compatibility archive libc identity changed')
        data = path.read_bytes()
        return dict(kind='musl-compatibility-archive', object_count=0, machine=None,
                    target=selected.rust_target, sha256=hashlib.sha256(data).hexdigest(),
                    bytes=len(data), libc_sha256=libc['sha256'])
