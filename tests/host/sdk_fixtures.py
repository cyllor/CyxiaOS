"""Small hand-built ELF archives for build-boundary tests, never guest evidence."""
import struct


def object_archive(machines):
    result = bytearray(b'!<arch>\n')
    for index, machine in enumerate(machines):
        body = bytearray(64)
        body[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HH', body, 16, 1, machine)
        header = f'{index}.o/'.ljust(16) + '0'.ljust(12) + '0'.ljust(6) + '0'.ljust(6) + '644'.ljust(8) + str(len(body)).ljust(10) + '`\n'
        result += header.encode() + body
    return result
