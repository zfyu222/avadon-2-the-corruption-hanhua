from collections import Counter
from pathlib import Path
import hashlib
import json
import re
import struct
import sys

from inspect_scripts import ROOT, strings

sys.path.insert(0, str(ROOT.parents[1] / 'Tools/localization'))
from workflow_resource_occurrences import column, export_occurrences, sha

GAME = ROOT / 'Game'
EXTRACTION = ROOT / 'Extraction'
DATA = 'Avadon 2 Files/Av2ScenData.dat'
EXE = 'Avadon 2.exe'
EXE_HASH = '893d26e896c58d6208eac56275cf961d87b48eb91ad891c5815a5485f2decfa1'
DATA_HASH = 'a2889e1578de4902da773f85ec1ea27b8caadce88c6879f461c9952ec0a98845'
SOURCE = ROOT / 'avadon-2_text.csv'
DISPLAY_ASSIGNMENTS = {
    'NUMBER', 'question', 'it_name', 'ab_name', 'cr_name', 'tr_name', 'ob_name', 'fl_name',
    *(f'text{i}' for i in range(1, 9)),
}
DISPLAY_CALLS = {
    'set_name', 'give_char_text_bubble', 'print_str', 'set_top_string',
    'set_terrain_string_range', 'run_text_on_char', 'begin_shop_mode',
    'print_str_color', 'create_text_bubble', 'print_big_str_color',
    'print_named_str', 'show_object_disarm_window',
}
NATIVE_RANGES = (
    (0x5c2950, 0x5c2afc),    # Graphics initialization messages
    (0x5c2c80, 0x5c3a68),    # Tutorial, world navigation and main UI
    (0x5c525c, 0x5c5378),    # Dialogue UI
    (0x5c5610, 0x5c57d0),    # Script-triggered game messages
    (0x5c5e18, 0x5cf400),    # In-game displays and player-facing errors
    (0x5e96c8, 0x5ec5b0),    # Medals
    (0x5ecd36, 0x5ed420),    # Controls settings
    (0x5edf00, 0x5edf64),    # Character classes
    (0x5efea0, 0x5effd0),    # Damage types and file-picker labels
)
PRINTF = re.compile(r'%(?:%|[-+ #0-9.*hlL]*[A-Za-z])')
INTERNAL = re.compile(
    r'https?://|\\\.\\|\.(?:txt|dat|tga|bmp|png|ogg|sav|exe|dll)(?:$|%)|'
    r'_(?=[a-z])|^\s*(?:debug\b|(?:char using|abil slot|talking error|shop error)\b)',
    re.I,
)


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def script_rows():
    for row in strings():
        kind, field = row['context'].split(':', 1) if ':' in row['context'] else ('', row['context'])
        if row['context'] in ('assign:ob_default_script', 'assign:cr_default_script'):
            continue
        if not row['text'].strip():
            continue
        if not ((kind == 'assign' and field in DISPLAY_ASSIGNMENTS) or
                (kind == 'call' and field in DISPLAY_CALLS)):
            raise ValueError(f"Unclassified script string at {row['file']}:{row['line']}")
        yield dict(row, encoding='cp1252', kind='script')


def dat_rows():
    raw = (GAME / DATA).read_bytes()
    if hashlib.sha256(raw).hexdigest() != DATA_HASH:
        raise ValueError('Unsupported scenario DAT')
    zones = struct.unpack_from('<H', raw)[0]
    if zones != 21 or len(raw) != 0x1168 + zones * 0x457ec:
        raise ValueError('Unexpected scenario DAT layout')

    def field(offset, capacity, context, **metadata):
        slot = raw[offset:offset + capacity]
        payload, nul, _ = slot.partition(b'\0')
        if not nul or any(byte < 32 for byte in payload):
            raise ValueError(f'Invalid DAT string field at {offset:#x}')
        if payload.strip():
            return dict(text=payload.decode('cp1252'), file=DATA, offset=offset,
                        length=len(payload), capacity=capacity, context=context, encoding='cp1252',
                        kind='scenario', **metadata)
        return None

    for zone in range(zones):
        row = field(4 + zone * 44, 32, 'zone_name', zone=zone)
        if row:
            yield row
        for layer in range(2):
            base = 0x1168 + zone * 0x457ec + layer * 0x1a3d8
            for slot in range(20):
                row = field(base + 0x1a0a4 + slot * 40, 40, 'map_label',
                            zone=zone, layer=layer, slot=slot)
                if row:
                    yield row


def native_rows():
    raw = (GAME / EXE).read_bytes()
    evidence = json.loads((ROOT / 'Analysis/ghidra-strings.json').read_text(encoding='utf-8-sig'))
    if hashlib.sha256(raw).hexdigest() != EXE_HASH or evidence['subject']['digest']['sha256'] != EXE_HASH:
        raise ValueError('Executable differs from the analyzed Steam build')
    pe = struct.unpack_from('<I', raw, 0x3c)[0]
    section_count = struct.unpack_from('<H', raw, pe + 6)[0]
    opt_size = struct.unpack_from('<H', raw, pe + 20)[0]
    image_base = struct.unpack_from('<I', raw, pe + 24 + 28)[0]
    sections = [
        struct.unpack_from('<III', raw, pe + 24 + opt_size + i * 40 + 12)
        for i in range(section_count)
    ]
    for item in evidence['normalized_result']:
        address = int(item['address'], 16)
        source = item['value']
        if address not in {0x5c20a0, 0x5c2afc} and not any(
                start <= address < end for start, end in NATIVE_RANGES):
            continue
        if not re.search('[A-Za-z]', PRINTF.sub('', source)) or INTERNAL.search(source):
            continue
        rva = address - image_base
        va, size, pointer = next(section for section in sections if section[0] <= rva < section[0] + section[1])
        offset = pointer + rva - va
        for encoding in ('cp1252', 'utf-16-le'):
            try:
                original = source.encode(encoding)
            except UnicodeEncodeError:
                continue
            nul = '\0'.encode(encoding)
            if raw[offset:offset + len(original + nul)] == original + nul:
                yield dict(text=source, file=EXE, offset=offset, length=len(original),
                           encoding=encoding, capacity=len(original + nul), context='native_literal',
                           kind='native', address=hex(address), rva=hex(rva),
                           evidence_id=evidence['evidence_id'])
                break
        else:
            raise ValueError(f'Executable source bytes differ at {address:#x}')


def main():
    rows = [*script_rows(), *dat_rows(), *native_rows()]
    sources = {file: (GAME / file).read_bytes() for file in {row['file'] for row in rows}}
    for row in rows:
        offset = row['offset']
        if row['text'].encode(row['encoding']) != sources[row['file']][offset:offset + row['length']]:
            raise ValueError(f"Source bytes differ at {row['file']}#{offset:#x}")
        row['source'] = row.pop('text')
        row['resource'] = f"{row['file']}#offset={offset:#x}"
    mapping = SOURCE.with_suffix('.mapping.json')
    export_occurrences(rows, SOURCE, mapping)
    indexed = json.loads(mapping.read_text(encoding='utf-8'))
    for identity, row in zip(indexed['records'], rows, strict=True):
        identity.update({key: value for key, value in row.items() if key not in ('source', 'statement', 'resource')})
    write_json(mapping, indexed)
    if column(SOURCE) != [row['source'] for row in rows]:
        raise ValueError('CSV round trip mismatch')
    context = {
        str(ordinal): dict(group=row['kind'], resource=row['resource'], text_type=row['context'],
                           scene=Path(row['file']).stem if row['kind'] == 'script' else '',
                           note=row.get('statement', ''))
        for ordinal, row in enumerate(rows, 1)
    }
    write_json(EXTRACTION / 'source_context.json', context)
    write_json(EXTRACTION / 'source_manifest.json',
               {file: dict(sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
                for file, raw in sorted(sources.items())})
    report = dict(records=len(rows), by_kind=dict(Counter(row['kind'] for row in rows)),
                  script_files=len(list((GAME / 'Avadon 2 Files/Scripts').glob('*.txt'))),
                  source_sha256=sha(SOURCE), mapping_sha256=sha(mapping))
    write_json(EXTRACTION / 'report.json', report)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

