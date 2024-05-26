#!/usr/bin/env python3

# seag-rom2elf
# Copyright (C) 2024 wilszdev
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import importlib
import struct
import sys

from parse import build_root_container, File

uncprs = importlib.import_module("seag-cprs.uncprs")
unlzma = importlib.import_module("seag-lzma.unlzma")


ERR_OK        = 0x00
ERR_USAGE     = 0x01
ERR_ROM_FILE  = 0x02
ERR_ROM2ELF   = 0x04
ERR_OUT_FILE  = 0x08


def main() -> int:
    if len(sys.argv) not in (2, 3):
        sys.stderr.write(f'Usage: {sys.argv[0]} INPUTFILE [OUTPUTFILE]\n')
        return ERR_USAGE

    try:
        inputFile = sys.stdin.buffer if sys.argv[1] == '-' else open(sys.argv[1], 'rb')
    except OSError:
        sys.stderr.write(f'Error: Unable to open file {sys.argv[1]}\n')
        return ERR_CPRS_FILE

    with inputFile:
        inputData = inputFile.read()

    if not (elf := rom2elf(inputData)):
        return ERR_UNCPRS

    try:
        outputFile = sys.stdout.buffer if len(sys.argv) == 2 else open(sys.argv[2], 'wb')
    except OSError:
        sys.stderr.write(f'Error: Unable to open file {sys.argv[2]} for writing\n')
        return ERR_OUT_FILE

    with outputFile:
        writeCount = outputFile.write(elf)

    if writeCount != len(elf):
        sys.stderr.write(f'Error: Failed to write all data to file {sys.argv[2]}\n')
        return ERR_OUT_FILE

    return ERR_OK


# for the elf header
OSABI_SYSV    = 0x00
ET_EXEC       = 0x02
MACHINE_ARM   = 0x28


# for program header (segments)
PT_NULL       = 0x00
PT_LOAD       = 0x01
PF_X          = 0x01
PF_W          = 0x02
PF_R          = 0x04


# for section header
SHT_NULL      = 0x00
SHF_NONE      = 0x00


class Elf32:
    def __init__(self):
        self.segments: list[tuple[bytes, int]] = []

    def add_segment(self, data: bytes, address: int) -> None:
        self.segments.append((data, address))

    @staticmethod
    def elf32_header(osabi, type, machine, entry, phoff, shoff, flags, phnum, shnum, shstrndx):
        return struct.pack('<8B8xHH5I6H',
                0x7f, ord('E'), ord('L'), ord('F'), 1, 1, 1, osabi,
                type, machine, 1, entry, phoff, shoff,
                flags, 0x34, 0x20, phnum, 0x28, shnum, shstrndx)

    @staticmethod
    def program_header(type, offset, vaddr, paddr, filesz, memsz, flags=PF_X|PF_W|PF_R, align=0):
        return struct.pack('<8I', type, offset, vaddr, paddr, filesz, memsz, flags, align)

    @staticmethod
    def section_header(name, type, flags, addr, offset, size, link, info, addralign, entsize=0):
        return struct.pack('<10I', name, type, flags, addr, offset, size, link, info, addralign, entsize)

    def to_blob(self) -> bytes:
        # offset of the actual data in the segments
        offset = 0x34 + 0x20 * len(self.segments) + 0x28

        blob = self.elf32_header(
                OSABI_SYSV, ET_EXEC, MACHINE_ARM, 0,
                # offsets to program and section header tables
                0x34, 0x34 + 0x20 * len(self.segments),
                # number of program/section headers
                0, len(self.segments),
                0, 0)

        for data, address in self.segments:
            blob += self.program_header(PT_LOAD, offset, address, 0, len(data), len(data))
            offset += len(data)

        blob += self.section_header(0, SHT_NULL, SHF_NONE, 0, 0, 0, 0, 0, 0, 0)

        for data, address in self.segments:
            blob += data

        return blob


def rom2elf(data: bytes) -> bytes:
    root = build_root_container(data)

    # find all the Files
    files = []

    toCheck = [root]
    while toCheck:
        newToCheck = []
        for element in toCheck:
            for child in element.elements:
                if isinstance(child, File):
                    files.append(child)
                else:
                    newToCheck.append(child)
        toCheck = newToCheck

    elf = Elf32()

    for file in files:
        data = file.blob
        if file.packed and data[:4] == b'CPRS':
            data = uncprs.decompress(data)
        elif file.packed and data[:4] == b'LZMA':
            data = unlzma.decompress(data)
        elf.add_segment(data, file.loadAddress)

    return elf.to_blob()


if __name__ == '__main__':
    exit(main())

