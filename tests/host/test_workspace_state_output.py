"""Compile the observer's actual reporting code with a serial write seam."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_governance_billing_priority import function

ROOT = Path(__file__).resolve().parents[2]


class WorkspaceStateOutput(unittest.TestCase):
    def test_complete_records_and_failed_short_write(self):
        source = (ROOT / 'user/ported/workspace_state_probe.c').read_text()
        start = source.index('    unsigned live = 0, active = 0;')
        report = source[start:source.index('    wl_registry_destroy(registry);', start)]
        helpers = '\n'.join(function(source, signature) for signature in
                            ('static int write_state_record(', 'static int report_workspace(')
                            if signature in source)
        expected = ('WORKSPACE_STATE workspace name_hex=31 active=1 tiling=0\n'
                    'WORKSPACE_STATE workspace name_hex=' + 'ff' * 127 + ' active=0 tiling=1\n'
                    'WORKSPACE_STATE PASS workspaces=2 active=1\n')
        fixture = r'''
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

struct workspace { char name[128]; uint32_t state, tiling; int named, tiled, removed; };
static struct workspace workspaces[2] = {
    { .name = "1", .state = 1, .named = 1, .tiled = 1 },
    { .tiling = 1, .named = 1, .tiled = 1 },
};
static size_t count = 2;
static int invalid, completed = 1, manager = 1, cosmic_manager = 1;
static int writes, partial_line, short_write;
static size_t used;
static char received[1024];

static ssize_t observe_record(int fd, const void *data, size_t size) {
    const char *line = data;
    if (fd != STDOUT_FILENO || size == 0 || line[size - 1] != '\n' ||
        memchr(line, '\n', size - 1) != NULL) {
        partial_line = 1;
        return size;
    }
    if (++writes == 1 && short_write) return size - 1;
    if (used + size >= sizeof(received)) return -1;
    memcpy(received + used, data, size);
    used += size;
    return size;
}

static ssize_t observed_write(int fd, const void *data, size_t size) {
    return observe_record(fd, data, size > 64 ? 64 : size);
}

static ssize_t observed_writev(int fd, const struct iovec *vectors, int count) {
    char record[1024];
    size_t size = 0;
    if (count <= 0 || count > 16) return -1;
    for (int index = 0; index < count; index++) {
        size_t length = vectors[index].iov_len;
        if (length == 0 || length > 64) return -1;
        memcpy(record + size, vectors[index].iov_base, length);
        size += length;
    }
    return observe_record(fd, record, size);
}

static int observed_printf(const char *format, ...) {
    char bytes[512];
    va_list args;
    va_start(args, format);
    int size = vsnprintf(bytes, sizeof(bytes), format, args);
    va_end(args);
    if (size < 0 || (size_t)size >= sizeof(bytes)) return -1;
    return (int)observed_write(STDOUT_FILENO, bytes, (size_t)size);
}

#define printf observed_printf
#define write observed_write
#define writev observed_writev
/* HELPER */
int main(int argc, char **argv) {
    (void)argv;
    short_write = argc > 1;
    memset(workspaces[1].name, 0xff, sizeof(workspaces[1].name) - 1);
/* REPORT */
    if (partial_line || writes != 3) {
        fputs("observer split a state record across writes\n", stderr);
        return 1;
    }
    if (short_write) return passed || strstr(received, "WORKSPACE_STATE PASS") != NULL;
    return !passed || strcmp(received, /* EXPECTED */) != 0;
}
'''
        fixture = (fixture.replace('/* HELPER */', helpers)
                   .replace('/* REPORT */', report)
                   .replace('/* EXPECTED */', json.dumps(expected)))
        with tempfile.TemporaryDirectory(prefix='cyxia-workspace-output-') as temporary:
            directory = Path(temporary)
            code = directory / 'output.c'
            binary = directory / 'output'
            code.write_text(fixture)
            built = subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                                    '-Wno-unused-function', str(code), '-o', str(binary)],
                                   capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            for args in ([], ['short']):
                with self.subTest(short_write=bool(args)):
                    ran = subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=10)
                    self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)


if __name__ == '__main__':
    unittest.main()
