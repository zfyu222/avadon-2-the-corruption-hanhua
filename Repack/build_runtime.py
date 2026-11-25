"""Build the Avadon 2 resource-indexed x86 localization prototype."""
import argparse
from collections import Counter, defaultdict
import csv
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
from tempfile import TemporaryDirectory

from stage_text import PROJECT, original_resource, read_json, sha, stage


REPACK = PROJECT / 'Repack'
WORKSPACE = PROJECT.parents[1]
PREVIOUS = PROJECT.parent / 'avadon-the-black-fortress' / 'Repack'
EXE = 'Avadon 2.exe'
LAYOUT = (0x487760, '558bec81ec80080000')
MEASURE = (0x4875e0, '558bec81ec30040000')
SPRINTF = (0x4c44b5, '8bff558bec83ec20')
FORMAT = re.compile(r'%(?:%|(?:[0-9]+\$)?[-+0#]*\d*(?:\.\d+)?(?:hh|ll|[hlLzjt])?[diuoxXfFeEgGaAcsp])')
MARKER = re.compile(rb'~[0-9A-Za-z]{3}~')
BASE36 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
WIDE_FILTER_PATTERNS = {0x5eff38: '*.sav', 0x5eff7c: '*.txt', 0x5effae: '*.*'}


def previous_build_tools():
    spec = importlib.util.spec_from_file_location('avadon_first_build', PREVIOUS / 'build_patch.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mark_resource(row):
    ordinal = row['ordinal']
    if not 0 < ordinal < 36 ** 3:
        raise ValueError(f"Ordinal does not fit the resource marker: {ordinal}")
    marker = ('~' + BASE36[ordinal // 1296] + BASE36[ordinal // 36 % 36]
              + BASE36[ordinal % 36] + '~').encode('ascii')
    original = row['source']
    target = row['translation']
    if row['file'].casefold().endswith('dlg.txt') and '_' in original:
        parts = target.split('_')
        opening = not (len(parts) == 2 and not parts[-1].strip())
        target = parts[0]
        for part in parts[1:]:
            target += ('“' if opening else '”') + part
            opening = not opening
    if row['kind'] == 'scenario':
        if len(marker) >= row['capacity']:
            raise ValueError(f"Marker exceeds DAT field capacity: {row['resource']}")
        return marker + b'\0' * max(1, row['length'] + 1 - len(marker)), target
    # The tutorial menu uses a leading dollar as a heading flag before rendering.
    if row['context'] == 'assign:NUMBER' and original.startswith('$'):
        if not target.startswith('$'):
            raise ValueError(f"Tutorial heading marker changed: {row['resource']}")
        return b'$' + marker, target[1:]
    return marker, target


def inherited_ui_records(executable, first):
    source = PREVIOUS.parent / 'avadon-the-black-fortress_text.csv'
    translated = source.with_name(source.stem + '_translated.csv')
    slots = {'Hard': (0x5cc288, 0x5cd7ec), 'Wait': (0x5ed006,)}
    candidates = defaultdict(set)
    with source.open(encoding='utf-8-sig', newline='') as originals, \
            translated.open(encoding='utf-8-sig', newline='') as translations:
        for original, target in zip(csv.reader(originals), csv.reader(translations), strict=True):
            if len(original) == 1 and original[0] in slots:
                candidates[original[0]].add(target[0])
    for label, addresses in slots.items():
        if len(candidates[label]) != 1:
            raise ValueError(f'The first game needs one approved translation for {label}')
        raw = label.encode('ascii')
        for address in addresses:
            offset = first.pe_file_offset(executable, address)
            if executable[offset:offset + len(raw) + 1] != raw + b'\0':
                raise ValueError(f'Native label changed at {address:#x}')
            yield address - 0x400000, raw, next(iter(candidates[label]))


def wide_ui_record(row, executable):
    original = row['source']
    target = row['translation']
    address = int(row['address'], 16)
    offset = row['offset']
    expected = original.encode('utf-16-le')
    pattern = WIDE_FILTER_PATTERNS.get(address)
    suffix = '\0' if pattern is None else '\0' + pattern + '\0'
    if pattern == '*.*':
        suffix += '\0'
    source = expected + suffix.encode('utf-16-le')
    if executable[offset:offset + len(source)] != source or '\0' in target:
        raise ValueError(f"Wide window text changed: {row['resource']}")
    target_bytes = len(target.encode('utf-16-le'))
    if target_bytes > len(expected):
        raise ValueError(f"Wide window text exceeds its slot: {row['resource']}")
    # Keep filter labels, patterns and both terminators at their original offsets.
    padding = ' ' if pattern is not None else '\0'
    target += padding * ((len(expected) - target_bytes) // 2)
    return int(row['rva'], 16) | 0x40000000, expected, target


def write_assets(game, payload, staged, executable, first):
    pending = defaultdict(list)
    modes = Counter()
    entries = []
    names = defaultdict(set)
    for row in staged['records']:
        if row['context'] in ('call:set_name', 'assign:cr_name'):
            names[row['source']].add(row['translation'])
        if row['source'] == row['translation']:
            modes['preserved'] += 1
            continue
        if row['kind'] == 'native':
            if row['encoding'] == 'utf-16-le':
                entries.append(wide_ui_record(row, executable))
                modes['native_wide'] += 1
                continue
            substitutions = FORMAT.findall(row['source'])
            if (row['encoding'] != 'cp1252'
                    or substitutions != FORMAT.findall(row['translation'])):
                modes['native_other_path'] += 1
                continue
            address = int(row['rva'], 16)
            entries.append((address | (0x80000000 if substitutions else 0),
                            row['source'].encode('cp1252'), row['translation']))
            modes['native_printf' if substitutions else 'native_pointer'] += 1
            continue
        if FORMAT.search(row['source']):
            modes['script_format_pending'] += 1
            continue
        pending[row['file']].append(row)
    inherited = list(inherited_ui_records(executable, first))
    entries.extend(inherited)
    modes['inherited_short_ui'] = len(inherited)
    # Character creation uses a separate Male literal for each selection state.
    # Neither four-byte literal was included in the original extraction.
    for address in (0x5ccc4c, 0x5ccc54):
        offset = first.pe_file_offset(executable, address)
        if executable[offset:offset + 5] != b'Male\0':
            raise ValueError(f'Native character creation label changed at {address:#x}')
        entries.append((address - 0x400000, b'Male', '男性'))
        modes['native_gender_label'] += 1
    for index, (source, targets) in enumerate(sorted(names.items()), 1):
        if len(targets) == 1 and source not in targets:
            entries.append((0xc0000000 | index, source.encode('cp1252'), next(iter(targets))))
            modes['actor_name_alias'] += 1
    source_manifest = read_json(PROJECT / 'Extraction/source_manifest.json')
    for name, records in pending.items():
        original = original_resource(game, name, source_manifest[name])
        if MARKER.search(original):
            raise ValueError(f'Original resource contains a reserved marker: {name}')
        replaced = bytearray()
        prior = 0
        for row in sorted(records, key=lambda row: row['offset']):
            offset, length = row['offset'], row['length']
            if offset < prior or original[offset:offset + length] != row['source'].encode('cp1252'):
                raise ValueError(f"Original occurrence changed: {row['resource']}")
            replacement, target = mark_resource(row)
            if row['kind'] == 'scenario':
                if original[offset + length] != 0:
                    raise ValueError(f"Expected a DAT terminator at {row['resource']}")
                length = max(length + 1, len(replacement))
                if any(original[offset + row['length']:offset + length]):
                    raise ValueError(f"DAT padding differs at {row['resource']}")
            replaced += original[prior:offset] + replacement
            prior = offset + length
            entries.append((0, str(row['ordinal']).encode('ascii'), target))
            modes[row['kind']] += 1
        replaced += original[prior:]
        if records[0]['kind'] == 'scenario' and len(replaced) != len(original):
            raise ValueError('Scenario data layout changed')
        target_path = payload / name
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(replaced)
    dictionary = payload / 'Avadon2Chinese' / 'resources.bin'
    dictionary.parent.mkdir()
    with dictionary.open('wb') as output:
        output.write(b'AV2LOC3\0' + struct.pack('<I', len(entries)))
        for address, original, target in entries:
            translated = target.encode('utf-8')
            output.write(struct.pack('<III', address, len(original), len(translated)))
            output.write(original + translated)
    return modes


def compile_runtime(build, payload, first):
    minhook = WORKSPACE / 'Tools/native/MinHook'
    commit = subprocess.check_output(['git', '-C', str(minhook), 'rev-parse', 'HEAD'], text=True).strip()
    if commit != first.MINHOOK_COMMIT:
        raise ValueError('MinHook differs from the version reviewed for the first game')
    variables, dumpbin = first.compiler()
    first.BUILD = build
    first.forwarders(dumpbin)
    shutil.copy2(minhook / 'LICENSE.txt', payload / 'Avadon2Chinese/MinHook-LICENSE.txt')
    quote = lambda path: f'"{path}"'
    obj = build / 'obj'
    obj.mkdir()
    commands = ['@echo off', 'call ' + quote(variables) + ' >nul', 'if errorlevel 1 exit /b 1']
    objects = []
    for source in ('src/buffer.c', 'src/hook.c', 'src/trampoline.c', 'src/hde/hde32.c'):
        file = obj / (Path(source).stem + '.obj')
        objects.append(quote(file))
        commands.extend(['cl /nologo /c /O2 /MT /TC /I' + quote(minhook / 'include') + ' '
                         + quote(minhook / source) + ' /Fo' + quote(file), 'if errorlevel 1 exit /b 1'])
    adapter = quote(REPACK / 'native/adapter.cpp')
    includes = ' '.join('/I' + quote(folder) for folder in (minhook / 'include', build, PREVIOUS / 'native'))
    commands.append(f'cl /nologo /std:c++17 /utf-8 /O2 /MT /EHsc /LD {includes} {adapter} '
                    + ' '.join(objects) + ' /Fo' + quote(obj / 'adapter.obj')
                    + ' /link /DEF:' + quote(build / 'winmm.def') + ' /OUT:' + quote(payload / 'winmm.dll'))
    commands.append('if errorlevel 1 exit /b 1')
    fixture = build / 'offline_test.exe'
    commands.append(f'cl /nologo /std:c++17 /utf-8 /O2 /MT /EHsc /DAV2_OFFLINE_TEST {includes} {adapter} '
                    + ' '.join(objects) + ' /Fo' + quote(obj / 'offline_test.obj')
                    + ' /link /OUT:' + quote(fixture))
    script = build / 'compile.cmd'
    script.write_bytes(('\r\n'.join(commands) + '\r\n').encode('utf-8'))
    process = subprocess.run(['cmd.exe', '/d', '/c', str(script)], cwd=build, capture_output=True)
    if process.returncode:
        raise RuntimeError((process.stdout + process.stderr).decode('oem', errors='replace')[-6500:])
    subprocess.run([str(fixture), str(payload / 'Avadon2Chinese')], check=True,
                   timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)


def build(output):
    output = output.resolve()
    game = (PROJECT / 'Game').resolve()
    if output.exists() or output.is_relative_to(game):
        raise ValueError('Expected a new output directory outside the Steam installation')
    output.parent.mkdir(parents=True, exist_ok=True)
    first = previous_build_tools()
    executable = (game / EXE).read_bytes()
    for address, expected in (LAYOUT, MEASURE, SPRINTF):
        offset = first.pe_file_offset(executable, address)
        if executable[offset:offset + len(expected) // 2].hex() != expected:
            raise ValueError(f'Unexpected function prologue at {address:#x}')
    with TemporaryDirectory(prefix='.avadon2-runtime-', dir=output.parent) as temporary:
        root = Path(temporary)
        input_path = root / 'occurrences.json'
        stage(PROJECT, input_path)
        staged = read_json(input_path)
        payload = root / 'payload'
        payload.mkdir()
        modes = write_assets(game, payload, staged, executable, first)
        compile_runtime(root, payload, first)
        compiler = Path('C:/Windows/Microsoft.NET/Framework/v4.0.30319/csc.exe')
        subprocess.run([str(compiler), '/nologo', '/target:winexe', '/optimize+',
                        f'/out:{payload / "Enhancement-Settings.exe"}',
                        '/reference:System.Drawing.dll', '/reference:System.Windows.Forms.dll',
                        str(REPACK / 'EnhancementSettings.cs')], check=True, timeout=30,
                       creationflags=subprocess.CREATE_NO_WINDOW)
        files = {str(path.relative_to(payload).as_posix()): sha(path.read_bytes())
                 for path in sorted(payload.rglob('*')) if path.is_file()}
        report = {'status': 'built_for_runtime_test', 'installed': False, 'exe_sha256': sha(executable),
                  'offline_formatter_test': 'passed', 'offline_wide_filter_test': 'passed',
                  'offline_enhancement_logic_test': 'passed',
                  'offline_copied_ui_and_inventory_title_test': 'passed',
                  'offline_dialogue_and_tooltip_test': 'passed',
                  'offline_quicksave_and_keyboard_test': 'passed',
                  'offline_camera_actor_layer_test': 'passed',
                  'offline_character_gender_labels_test': 'passed',
                  'translation_sha256': staged['translation_sha256'], 'records_by_mode': dict(modes),
                  'files': files}
        first.write_json(payload / 'RUNTIME_PAYLOAD.json', report)
        payload.rename(output)
    return {'records_by_mode': modes, 'files': len(files)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    print(json.dumps(build(parser.parse_args().out), ensure_ascii=False))
