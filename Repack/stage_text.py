"""Bind an approved Chinese corpus to the exact Avadon 2 resource occurrences."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT.parents[1] / 'Tools/localization'))
from workflow_resource_occurrences import ResourceResolver


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def original_resource(game, name, identity):
    for directory in (game, game / '.zfy-localization/original'):
        path = (directory / name).resolve()
        if not path.is_relative_to(directory.resolve()) or not path.is_relative_to(game):
            raise ValueError(f'Original resource is outside the game directory: {name}')
        if path.is_file():
            content = path.read_bytes()
            if len(content) == identity['size'] and sha(content) == identity['sha256']:
                return content
    raise ValueError(f'No resource matches the extraction hash: {name}')


def stage(project, output):
    source = project / 'avadon-2_text.csv'
    translated = project / 'avadon-2_text_translated.csv'
    mapping_path = source.with_suffix('.mapping.json')
    report = read_json(project / 'TranslateFiles/reports/final_validation.json')
    source_hash = sha(source.read_bytes())
    translation_hash = sha(translated.read_bytes())
    if (report.get('status') != 'passed' or report.get('semantic_review') != 'full'
            or report.get('source_sha256') != source_hash
            or report.get('translation_sha256') != translation_hash):
        raise ValueError('Expected the current formally validated translation')
    extraction = read_json(project / 'Extraction/report.json')
    mapping_bytes = mapping_path.read_bytes()
    if sha(mapping_bytes) != extraction['mapping_sha256']:
        raise ValueError('The extracted resource mapping changed')
    mapping = json.loads(mapping_bytes)['records']
    resolver = ResourceResolver(source, translated, mapping_path=mapping_path)
    if len(mapping) != len(resolver.targets) or len(mapping) != report['records']:
        raise ValueError('Translation and resource occurrence count mismatch')

    source_manifest = read_json(project / 'Extraction/source_manifest.json')
    executable = 'Avadon 2.exe'
    save_paths = read_json(project / 'Analysis/save-path-formats.json')
    if save_paths['exe_sha256'] != source_manifest[executable]['sha256']:
        raise ValueError('Save path exclusions belong to a different executable')
    excluded = {row['ordinal']: row for row in save_paths['occurrences']}
    if len(excluded) != len(save_paths['occurrences']):
        raise ValueError('Duplicate save path exclusions')
    originals = {}
    game = (project / 'Game').resolve()
    for name, identity in source_manifest.items():
        originals[name] = original_resource(game, name, identity)

    by_source = defaultdict(list)
    records = []
    preserved = []
    for entry in mapping:
        ordinal = entry['ordinal']
        name = entry['file']
        offset, length = entry['offset'], entry['length']
        raw = originals[name][offset:offset + length]
        original = raw.decode(entry['encoding'])
        if original != resolver.sources[ordinal - 1]:
            raise ValueError(f'Original bytes differ at {name} offset {offset:#x}')
        target = resolver.resolve(entry['resource'], original)
        record = {**entry, 'source': original, 'translation': target}
        exclusion = excluded.pop(ordinal, None)
        if exclusion is not None:
            if (name != executable or entry['kind'] != 'native' or original != exclusion['source']
                    or entry['address'] != exclusion['address']):
                raise ValueError(f'Save path exclusion differs from the bound occurrence {ordinal}')
            record.update(translation=original, preserve_reason='save_path_format')
            preserved.append(ordinal)
        records.append(record)
        by_source[original].append(record)
    resolver.finish()
    if excluded:
        raise ValueError('One or more save path exclusions did not match mapped occurrences')

    ambiguous = [{'source': original, 'ordinals': [row['ordinal'] for row in rows]}
                 for original, rows in by_source.items()
                 if len({row['translation'] for row in rows}) > 1]
    if output.resolve().is_relative_to(game):
        raise ValueError('Use a staging path outside the game directory')
    if output.exists():
        raise FileExistsError(output)
    staging = dict(status='occurrences_verified', source_sha256=source_hash,
                   translation_sha256=translation_hash, by_kind=dict(Counter(row['kind'] for row in records)),
                   requires_context=ambiguous, preserved_save_paths=preserved, records=records)
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix='.avadon2-text-', dir=output.parent) as temporary:
        ready = Path(temporary) / output.name
        with ready.open('w', encoding='utf-8') as handle:
            json.dump(staging, handle, ensure_ascii=False, indent=2)
            handle.write('\n')
        ready.rename(output)
    return dict(records=len(records), requires_context=len(ambiguous), preserved_save_paths=len(preserved))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    print(json.dumps(stage(PROJECT, parser.parse_args().out)))
