#!/usr/bin/env python3

# seag-romtools
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


import struct
import sys


ERR_OK    = 0x00
ERR_USAGE = 0x01


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write(f'Usage: {sys.argv[0]} FILE0 [FILE...]\n')
        return ERR_USAGE

    for filePath in sys.argv[1:]:
        try:
            inputFile = sys.stdin.buffer if filePath == '-' else open(filePath, 'rb')
        except OSError:
            sys.stderr.write(f'Error: Failed to open file {filePath}\n')
            continue

        with inputFile:
            data = inputFile.read()

        root = build_root_container(data)
        root.print()

    return ERR_OK


EXTRA_SPACE_ID    = 0x00
ROOT_CONTAINER_ID = 0x1d


# so that type hints work
class Element: pass


class Element:
    def __init__(self):
        self.id = 0xff
        self.elements: list[Element] = []

    def header_blob(self) -> bytes:
        return bytes()

    def footer_blob(self) -> bytes:
        return bytes()

    def to_blob(self) -> bytes:
        blob = self.header_blob()
        for element in self.elements:
            blob += element.to_blob()
        blob += self.footer_blob()
        return blob

    def print(self, level: int = 0) -> None:
        print(f'{"    " * level}{self.__class__.__name__} 0x{self.id:02x}: 0x{len(self.elements):02x} children. size=0x{len(self.to_blob()):06x}')
        for element in self.elements:
            element.print(level + 1)


class Blob(Element):
    def __init__(self, id: int, data: bytes):
        super().__init__()
        self.id = id
        self.data = data

    def header_blob(self) -> bytes:
        return self.data


class File(Element):
    CHUNK_SIZE = 0x40

    def __init__(self, data: bytes):
        super().__init__()

        self.packed, self.id, self.type, self.unknown, self.size, self.loadAddress = \
                self.parse_header(data[:8])

        self.blob = data[8:8+self.size]

    def header_blob(self) -> bytes:
        fileInfo = 0
        fileInfo |= (1 if self.packed else 0)
        fileInfo |= self.id << 1
        fileInfo |= self.type << 5
        fileInfo &= 0xff

        sizeBytes = len(self.blob) % File.CHUNK_SIZE

        sizeBytesAndUnknown = 0
        sizeBytesAndUnknown |= sizeBytes << 2
        sizeBytesAndUnknown |= self.unknown

        sizeChunks = len(self.blob) // File.CHUNK_SIZE

        return struct.pack('<BBHL',
                fileInfo, sizeBytesAndUnknown, sizeChunks, self.loadAddress)

    def footer_blob(self) -> bytes:
        return self.blob

    @staticmethod
    def parse_header(data: bytes):
        assert len(data) == 8
        # data is packed together in slightly annoying bit fields
        fileInfo, sizeBytesAndUnknown, sizeChunks, loadAddress = \
                struct.unpack('<BBHL', data)

        packed = (fileInfo & 1) == 1    # least significant bit is packed flag
        fileId = (fileInfo >> 1) & 0x0f # followed by 4-bit file id
        fileType = (fileInfo >> 5)      # followed by 3-bit file type

        sizeBytes = (sizeBytesAndUnknown & 0xf0) >> 2

        size = sizeChunks * File.CHUNK_SIZE + sizeBytes
        unknown = sizeBytesAndUnknown & 0x0f

        return packed, fileId, fileType, unknown, size, loadAddress


class Directory(Element):
    def __init__(self, id: int, data: bytes):
        super().__init__()
        self.id = id

        offset = 0
        while offset + 8 <= len(data):
            file = File(data[offset:])
            offset += len(file.to_blob())
            self.elements.append(file)
            if file.id == 0:
                break

        # remaining space is spare
        if offset != len(data):
            self.elements.append(Blob(0, data[offset:]))


class Container(Element):
    PRE_TABLE_HEADER_LENGTH = 32

    def __init__(self, id: int, data: bytes):
        super().__init__()
        self.id = id
        self.preSegmentTableHeader = data[:self.PRE_TABLE_HEADER_LENGTH]

        self.signature_assert(data)

        # parse the table, construct contents
        _, firstElementOffset = self.parse_entry(data[self.PRE_TABLE_HEADER_LENGTH:self.PRE_TABLE_HEADER_LENGTH+4])
        if firstElementOffset:
            elements = self.get_elements_old(data)
        else:
            elements = self.get_elements_new(data)

        for i in range(len(elements) - 1):
            currentId, currentOffset = elements[i]
            _, nextOffset = elements[i + 1]

            # carve out the data and decide the type
            elementData = data[currentOffset:nextOffset]
            if currentId == ROOT_CONTAINER_ID or currentOffset == 0:
                element = Blob(currentId, elementData)
            else:
                element = self.create_element(currentId, elementData)

            if element:
                self.elements.append(element)

        lastIndex = -1
        lastId, lastOffset = elements[lastIndex]
        while lastOffset == 0:
            lastIndex -= 1
            _, lastOffset = elements[lastIndex]
        lastData = data[lastOffset:]
        if element := self.create_element(lastId, lastData):
            self.elements.append(element)


    def get_elements_old(self, data: bytes):
        _, firstElementOffset = self.parse_entry(data[self.PRE_TABLE_HEADER_LENGTH:self.PRE_TABLE_HEADER_LENGTH+4])
        table = data[self.PRE_TABLE_HEADER_LENGTH:firstElementOffset]
        return [self.parse_entry(table[i:i+4]) for i in range(0, len(table), 4)]

    def get_elements_new(self, data: bytes):
        elements = []

        table = data[self.PRE_TABLE_HEADER_LENGTH:]
        tableOffset = 0
        while 1:
            id, offset = self.parse_entry(table[tableOffset:tableOffset+4])
            elements.append((id, offset))
            if id == EXTRA_SPACE_ID:
                return elements
            tableOffset += 4

    def signature_assert(self, data: bytes):
        pass

    @staticmethod
    def create_element(id: int, data: bytes):
        if len(data) > 36 and data[16:20] == b'csiD':
            return DiscContainer(id, data)

        if len(data) < 8:
            return Blob(id, data)

        *_, size, loadAddress = File.parse_header(data[:8])
        if 0 <= size <= len(data) and loadAddress != 0xffffffff:
            return Directory(id, data)

        return Blob(id, data)

    @staticmethod
    def parse_entry(data: bytes) -> tuple[int, int]:
        assert len(data) == 4
        data += b'\0'
        return struct.unpack('<BI', data)

    def header_blob(self) -> bytes:
        # if the first element is the root container ID, we don't
        # need to build the header blob.
        if self.elements and self.elements[0].id == ROOT_CONTAINER_ID:
            return bytes()

        # construct the segment table.
        # would help to figure out what some of the other parameters are
        # in the first 32 bytes, but not a big deal
        header = self.preSegmentTableHeader

        offset = len(header) + 4 * len(self.elements)
        for element in self.elements:
            header += struct.pack('<BI', element.id & 0xff, offset & 0xffffffff)[:4]
            size = len(element.to_blob())

            if size:
                offset += size
            else:
                offset = 0

        return header


class DiscContainer(Container):
    PRE_TABLE_HEADER_LENGTH = 32

    def signature_assert(self, data: bytes):
        assert data[16:20] == b'csiD'


class OldContainer(Container):
    PRE_TABLE_HEADER_LENGTH = 16

    def signature_assert(self, data: bytes):
        assert data[16:20] != b'csiD'


def build_root_container(data: bytes):
    # check for "Disc" signature to determine root container type
    if data[16:20] == b'csiD':
        return DiscContainer(ROOT_CONTAINER_ID, data)
    else:
        return OldContainer(ROOT_CONTAINER_ID, data)


if __name__ == '__main__':
    exit(main())
