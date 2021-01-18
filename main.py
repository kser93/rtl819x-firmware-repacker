#!/usr/bin/python3
import pathlib
from collections import defaultdict
import enum
import json
from argparse import ArgumentParser
from struct import unpack, calcsize, pack
import os
import tempfile


class Magic(enum.Enum):
    tail = b'TAIL'
    config = (b'COMP',)
    fw = (b'cs6b', b'cs6c', b'csys')
    fw_with_root = (b'cr6b', b'cr6c', b'csro')
    root = (b'r6br', b'r6cr', b'root')
    web = (b'w6bv', b'w6bg', b'w6ba', b'w6cv', b'w6cg', b'w6ca', b'webv', b'webg', b'weba')
    sapido_header = (b'296n', b'297n', b'C76n')


known_magics = defaultdict(lambda: Magic.tail)
for magic in Magic:
    if magic == Magic.tail:
        continue
    for signature in magic.value:
        known_magics[signature] = magic


def parse_tail(fd_firmware, signature):
    offset = fd_firmware.tell() - len(signature)
    data = signature + fd_firmware.read()
    return {
        'magic': known_magics[signature],
        'offset': offset,
        'length': len(data)
    }


def parse_config(fd_firmware, signature):
    offset = fd_firmware.tell() - len(signature)
    signature_tail_len = 2
    signature_tail = fd_firmware.read(signature_tail_len)
    if len(signature_tail) < signature_tail_len or signature_tail not in {b'CS', b'DS', b'HS'}:
        return parse_tail(fd_firmware, signature + signature_tail)

    pattern = '>IH'
    pattern_size = calcsize(pattern)
    header_rest = fd_firmware.read(pattern_size)
    if len(header_rest) < pattern_size:
        return parse_tail(fd_firmware, signature + signature_tail + header_rest)

    _, config_size = unpack(pattern, header_rest)
    config_rest = fd_firmware.read(config_size)
    if len(config_rest) < config_size:
        return parse_tail(fd_firmware, signature + signature_tail + config_rest)

    data = signature + signature_tail + header_rest + config_rest
    return {
        'magic': known_magics[signature],
        'offset': offset,
        'length': len(data)
    }


def parse_datablock(fd_firmware, signature):
    offset = fd_firmware.tell() - len(signature)
    pattern = '>3I'
    pattern_size = calcsize(pattern)
    header_rest = fd_firmware.read(pattern_size)
    if len(header_rest) < pattern_size:
        return parse_tail(fd_firmware, signature + header_rest)

    _, _, block_size = unpack(pattern, header_rest)
    block_body = fd_firmware.read(block_size)
    if len(block_body) < block_size:
        return parse_tail(fd_firmware, signature + header_rest + block_body)

    header = signature + header_rest
    return {
        'magic': known_magics[signature],
        'offset': offset,
        'length': len(header) + len(block_body),
        'content': {
            'header': {
                'offset': offset,
                'length': len(header)
            },
            'body': {
                'offset': offset + len(header),
                'length': len(block_body)
            }
        }
    }


def parse_sapido_header(fd_firmware, signature):
    offset = fd_firmware.tell() - len(signature)
    pattern = '>3I'
    pattern_size = calcsize(pattern)
    header_rest = fd_firmware.read(pattern_size)
    if len(header_rest) < pattern_size:
        return parse_tail(fd_firmware, signature + header_rest)

    data = signature + header_rest
    return {
        'magic': known_magics[signature],
        'offset': offset,
        'length': len(data)
    }


block_parsers = {
    Magic.tail: parse_tail,
    Magic.config: parse_config,
    Magic.fw: parse_datablock,
    Magic.fw_with_root: parse_datablock,
    Magic.root: parse_datablock,
    Magic.web: parse_datablock,
    Magic.sapido_header: parse_sapido_header,
}


def firmware_blocks(fd_firmware):
    while True:
        magic_len = 4
        signature = fd_firmware.read(magic_len)
        magic = known_magics.get(signature, Magic.tail)
        parsed = block_parsers[magic](fd_firmware, signature)
        yield parsed
        if parsed['magic'] == Magic.tail:
            break


def unpack_rootfs(fd_firmware, firmware_block, extract_path):
    old_offset = fd_firmware.tell()
    fd_firmware.seek(firmware_block['content']['body']['offset'])

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.rootfs', dir='.') as fd_temp:
        fd_temp.write(
            fd_firmware.read(firmware_block['content']['body']['length'])
        )
        os.system(f'unsquashfs -d {extract_path} {pathlib.Path(fd_temp.name)}')

    fd_firmware.seek(old_offset)


def cut_rootfs(fd_firmware, firmware_block, save_path):
    old_offset = fd_firmware.tell()
    fd_firmware.seek(firmware_block['content']['body']['offset'])

    with open(save_path, 'wb') as fd:
        fd.write(
            fd_firmware.read(firmware_block['content']['body']['length'])
        )

    fd_firmware.seek(old_offset)


def extract_firmware(firmware, extract_path, unpack: bool):
    firmware_structure = list()
    with open(firmware, 'rb') as fd_firmware:
        for firmware_block in firmware_blocks(fd_firmware):
            firmware_structure.append({
                **firmware_block,
                'magic': firmware_block['magic'].name,
            })
            if firmware_block['magic'] == Magic.root:
                if unpack:
                    unpack_rootfs(fd_firmware, firmware_block, extract_path)
                else:
                    cut_rootfs(fd_firmware, firmware_block, 'rootfs')
        with open('firmware_structure.json', 'w') as fd:
            json.dump(list(firmware_structure), fd, indent=4)


def validate(data):
    checksum = sum(
        unpack('>H', data[x: x + 2])[0]
        for x in range(0, len(data), 2)
    )
    return 0x10000 - (checksum & 0xFFFF)


def pack_rootfs(rootfs_path):
    with tempfile.NamedTemporaryFile(mode='rb', suffix='.rootfs', dir='.') as fd_temp:
        # TODO: generate mksquashfs args based on original rootfs
        os.system(' '.join([
            'mksquashfs',
            pathlib.Path(rootfs_path).as_posix(),
            pathlib.Path(fd_temp.name).as_posix(),
            '-comp xz',
            '-noX',
            '-no-recovery',
            '-no-xattrs',
            '-noappend'
        ]))
        rootfs_content = fd_temp.read()

    # compute 2-byte checksum and append at the end of rootfs
    return rootfs_content + pack('>H', validate(rootfs_content))


def pack_firmware(firmware, rootfs_path):
    with open('firmware_structure.json', 'r') as fd:
        firmware_structure = json.load(fd)

    with open(firmware, 'rb') as fd_firmware_orig, open(f'{firmware}.new', 'wb') as fd_firmware_new:
        for firmware_block in firmware_structure:
            if firmware_block['magic'] == Magic.root.name:
                rootfs_content = pack_rootfs(rootfs_path)
                fd_firmware_orig.seek(firmware_block['content']['header']['offset'])
                rootfs_header = fd_firmware_orig.read(firmware_block['content']['header']['length'])
                # new rootfs header
                print(rootfs_header)
                fd_firmware_new.write(rootfs_header[:-4] + pack('>I', len(rootfs_content)))
                fd_firmware_new.write(rootfs_content)
            else:
                fd_firmware_orig.seek(firmware_block['offset'])
                fd_firmware_new.write(
                    fd_firmware_orig.read(firmware_block['length'])
                )


def parse_args():
    parser = ArgumentParser(add_help=True)
    parser.add_argument('-f', dest='firmware', required=True, help='Path to firmware')
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('-c', dest='cut', action='store_true', help='Cut out rootfs', default=False)
    mode_group.add_argument('-u', dest='unpack', action='store_true', help='Unpack firmware', default=False)
    mode_group.add_argument('-p', dest='pack', action='store_true', help='Pack firmware', default=False)
    parser.add_argument('-d', dest='rootfs', help='Path to rootfs directory (default: squashfs-root)', default='squashfs-root')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    if args.cut:
        extract_firmware(args.firmware, args.rootfs, False)
    if args.unpack:
        extract_firmware(args.firmware, args.rootfs, True)
    if args.pack:
        pack_firmware(args.firmware, args.rootfs)
