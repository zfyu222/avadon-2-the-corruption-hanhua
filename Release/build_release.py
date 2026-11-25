"""Build and replay the Avadon 2 patch installer without launching the game."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile


PROJECT = Path(__file__).resolve().parents[1]
WORKSPACE = PROJECT.parents[1]
SCRIPTS = WORKSPACE / '.agents/skills/game-release-patch/scripts'
DISPATCH = PROJECT / 'Dispatch'
RUNTIME = PROJECT / 'ImagePatch/runtime-v11-polish'
GENDER_FIX = PROJECT / 'ImagePatch/runtime-v12-gender-label'
GENDER_CHECK = PROJECT / 'Repack/CHARACTER_GENDER_CHECK.json'
DICTIONARY = 'Avadon2Chinese/resources.bin'
IMAGES = PROJECT / 'ImagePatch/engine-stage-v1'
IMAGE_PROJECT = PROJECT / 'TranslateFiles/image-text'
GAME_NAME = '阿瓦登 2：腐化之地'
GAME_VERSION = 'Steam Build 4512909 / v1.0.1S'
PLATFORM = 'Steam Windows 版'
VERSION = '1.5'
ARCHIVE = DISPATCH / f'{GAME_NAME}_子非鱼汉化{VERSION}.zip'
PREVIOUS_ARCHIVE = DISPATCH / f'{GAME_NAME}_子非鱼汉化1.0.zip'
ADDON = DISPATCH / f'{GAME_NAME}_体验优化1.1.zip'
SETTINGS = 'Enhancement-Settings.exe'
EXE = 'Avadon 2.exe'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def bindings():
    runtime = load(RUNTIME / 'RUNTIME_PAYLOAD.json')
    fix = load(GENDER_FIX / 'RUNTIME_PAYLOAD.json')
    check = load(GENDER_CHECK)
    images = load(IMAGES / 'IMAGE_PAYLOAD.json')
    stock = (PROJECT / 'Game').resolve()
    exe_hash = sha(stock / EXE)
    if exe_hash != runtime['exe_sha256'] or exe_hash != images['exe_sha256']:
        raise ValueError('Payload and original executable versions differ')
    if (fix['exe_sha256'] != exe_hash or fix['translation_sha256'] != runtime['translation_sha256']
            or fix['offline_character_gender_labels_test'] != 'passed'
            or check['updated_game_files'] != {DICTIONARY: fix['files'][DICTIONARY]}):
        raise ValueError('Character creation fix does not match its verified payload')
    runtime['files'][DICTIONARY] = fix['files'][DICTIONARY]
    image_files = {row['path']: row['sha256'] for row in images['files']}
    if set(runtime['files']) & set(image_files):
        raise ValueError('Duplicate runtime and image installation targets')
    with zipfile.ZipFile(PREVIOUS_ARCHIVE) as previous:
        config = json.loads(previous.read('汉化工具/config.json').decode('utf-8-sig'))
    with zipfile.ZipFile(DISPATCH / f'{GAME_NAME}_子非鱼汉化1.4.zip') as previous:
        previous_files = {item['path']: item['sha256']
                          for item in json.loads(previous.read('PATCH_MANIFEST.json'))['files']}
    if config['exe_sha256'] != exe_hash:
        raise ValueError('Unsupported executable for upgrade')
    config['preserve_on_retire'] = [SETTINGS]
    entries = []
    for root, files in ((RUNTIME, runtime['files']), (IMAGES, image_files)):
        for target, checksum in sorted(files.items()):
            if target == SETTINGS:
                continue
            source = (GENDER_FIX if target == DICTIONARY else root) / target
            if target.casefold() == EXE.casefold() or sha(source) != checksum:
                raise ValueError(f'Invalid release payload at {target}')
            entries.append(dict(path=source.relative_to(PROJECT).as_posix(),
                                game_path=target, sha256=checksum))
    expected = {path: checksum for path, checksum in previous_files.items() if path != SETTINGS}
    current = {entry['game_path']: entry['sha256'] for entry in entries}
    if (current.keys() != expected.keys() or
            {path for path in current if current[path] != expected[path]} !=
            {DICTIONARY}):
        raise ValueError('Unexpected game payload change')
    if any(sha(stock / path) != checksum for path, checksum in current.items()):
        raise ValueError('Published payload must match the installed local fix')
    return entries, image_files, config


def original_file(path, expected):
    stock = PROJECT / 'Game'
    for candidate in (stock / path, stock / '.zfy-localization/original' / path):
        if candidate.is_file() and sha(candidate) == expected:
            return candidate
    raise ValueError(f'No verified original available for installer replay: {path}')


def accept(entries, images):
    sys.path.insert(0, str(WORKSPACE / 'Tools/localization'))
    from translation_workflow import Workflow

    authorization = PROJECT / 'Release/authorization.json'
    statement = load(authorization)['user_statement']
    image_evidence = IMAGE_PROJECT / 'release-textures'
    image_evidence.mkdir(exist_ok=True)
    local_auth = image_evidence / 'authorization.json'
    shutil.copyfile(authorization, local_auth)
    local_manifest = image_evidence / 'IMAGE_PAYLOAD.json'
    shutil.copyfile(IMAGES / 'IMAGE_PAYLOAD.json', local_manifest)
    image_entries = []
    for target, checksum in sorted(images.items()):
        staged = image_evidence / target
        staged.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(IMAGES / target, staged)
        image_entries.append(dict(path=staged.relative_to(IMAGE_PROJECT).as_posix(),
                                  game_path=target, sha256=checksum))
    body_translation = sha(PROJECT / 'avadon-2_text_translated.csv')
    image_translation = sha(IMAGE_PROJECT / 'avadon-2_images_text_translated.csv')
    if (body_translation != load(RUNTIME / 'RUNTIME_PAYLOAD.json')['translation_sha256']
            or image_translation != sha(PROJECT / 'avadon-2_images_text_translated.csv')):
        raise ValueError('Staged assets and final exports have different source versions')
    for root, translation, payload, evidence in (
        (PROJECT, body_translation, entries, (authorization, GENDER_CHECK,
                                              RUNTIME / 'RUNTIME_PAYLOAD.json', GENDER_FIX / 'RUNTIME_PAYLOAD.json',
                                              IMAGES / 'IMAGE_PAYLOAD.json')),
        (IMAGE_PROJECT, image_translation, image_entries, (local_auth, local_manifest)),
    ):
        flow = Workflow(root)
        flow.record_release_acceptance(dict(
            authorization='explicit_user_release', in_game_validation='pending',
            accept_pending_runtime=True, user_statement=statement,
            game_version=GAME_VERSION, platform=PLATFORM, translation_sha256=translation,
            payload_files=payload, evidence_files=[
                dict(path=path.relative_to(root).as_posix(), sha256=sha(path)) for path in evidence],
        ))
        if flow.release_check()['status'] != 'passed':
            raise ValueError(f'Could not verify the release for {root.name}')


def package(entries, config):
    links = load(PROJECT / 'Release/player_links.json')
    config_path = PROJECT / 'Release/installer_config.json'
    save(config_path, config)
    args = [sys.executable, str(SCRIPTS / 'create_release_patch.py'), '--project', str(PROJECT),
            '--game-name', GAME_NAME, '--chinese-name', GAME_NAME, '--english-name',
            'Avadon 2: The Corruption', '--version', VERSION,
            '--game-version', GAME_VERSION, '--platform', PLATFORM, '--release-date', '2026-11-25',
            '--introduction', '这是一款等距视角的奇幻小队角色扮演游戏。你将为黑色要塞效力，从五种职业中选择其一，带队探索地下城、完成支线，并在回合制战斗中运用职业技能。你对各方势力的选择将改变故事结局。',
            '--coverage', '简体中文剧情、对话、菜单、提示及 19 张含字贴图。\n\n'
            '体验优化补丁（可选，推荐使用）\n'
            '提供中文字号和短标签适配、镜头跟随、探索移速调整、再次按快捷键关闭背包，以及可互动物体标记。'
            '安装汉化后，另行下载并解压体验优化补丁。',
            '--install', '解压到 Avadon 2.exe 所在目录，双击“安装汉化.cmd”。',
            '--upgrade', '覆盖解压新版，双击“安装汉化.cmd”自动检测并升级旧版。',
            '--changes', '补齐角色创建界面「男性」标签在选中和未选中时的中文显示。',
            '--uninstall', '双击“卸载汉化.cmd”。', '--installer-config', str(config_path)]
    for key in ('steam_url', 'download_url', 'share_name', 'mirror_url'):
        args.extend(['--' + key.replace('_', '-'), links[key]])
    for entry in entries:
        args.extend(['--include', entry['path'] + '=' + entry['game_path']])
    dry_run = subprocess.run([*args, '--dry-run'], capture_output=True, check=True)
    if len(dry_run.stdout.splitlines()) != len(entries) + 1:
        raise ValueError('Unexpected dry-run file count')
    subprocess.run(args, check=True)


def verify(entries, config):
    metadata = {'补丁说明.txt', 'PATCH_MANIFEST.json', 'SHA256SUMS.txt'}
    installed = {item['game_path']: item['sha256'] for item in entries}
    original = {item['path']: item['sha256'] for item in config['originals']}
    original[EXE] = config['exe_sha256']
    with tempfile.TemporaryDirectory(prefix='av2-release-', dir=DISPATCH) as directory:
        root = Path(directory) / '阿瓦登 2 测试目录'
        root.mkdir()
        with zipfile.ZipFile(ARCHIVE) as archive:
            manifest = json.loads(archive.read('PATCH_MANIFEST.json'))
            if (archive.testzip() is not None
                    or {item['path']: item['sha256'] for item in manifest['files']} != installed):
                raise ValueError('Invalid archive data or payload manifest')
            checksums = {item.get('archive_path', item['path']): item['sha256']
                         for item in manifest['files'] + manifest['auxiliary']}
            archive_sums = {path: checksum for checksum, path in
                            (line.split('  ', 1) for line in archive.read('SHA256SUMS.txt').decode().splitlines())}
            if (archive_sums != checksums or set(archive.namelist()) != set(checksums) | metadata
                    or len(archive.namelist()) != len(checksums) + len(metadata)):
                raise ValueError('Unexpected archive entries')
            for path, checksum in checksums.items():
                if hashlib.sha256(archive.read(path)).hexdigest() != checksum:
                    raise ValueError(f'Archive checksum mismatch at {path}')
            archive.extractall(root)
            for path in metadata:
                (DISPATCH / path).write_bytes(archive.read(path))
        for path in original:
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original_file(path, original[path]), root / path)
        fixture_exe = 'Avadon2LocalizationInstallerFixture.exe'
        shutil.copyfile(root / EXE, root / fixture_exe)

        def assert_game(expected):
            for path in installed.keys() | original.keys() | {SETTINGS}:
                candidate = root / path
                if (sha(candidate) if candidate.is_file() else None) != expected.get(path):
                    raise ValueError(f'Unexpected replay output at {path}')

        def install(action, expected_code=0):
            script = root / '汉化工具/patch.ps1'
            # Match the original EXE hash under a fixture filename so an unrelated
            # game session does not trigger the installer's process check.
            fixture_config = script.with_name('config.json')
            fixture_settings = load(fixture_config)
            fixture_settings['exe'] = fixture_exe
            fixture_config.write_text(json.dumps(fixture_settings, ensure_ascii=False), encoding='utf-8-sig')
            proc = subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                                   '-File', str(script), '-Action', action, '-NoLaunch'],
                                  capture_output=True, timeout=60)
            if proc.returncode != expected_code:
                raise RuntimeError((proc.stdout + proc.stderr).decode('utf-8', errors='replace'))

        sample = next(item for item in manifest['files'] if item['path'] == 'Avadon2Chinese/MinHook-LICENSE.txt')
        staged = root / sample['archive_path']
        initial = staged.read_bytes()
        staged.write_bytes(b'corrupted delivery')
        install('install', expected_code=1)
        assert_game(original)
        staged.write_bytes(initial)
        with zipfile.ZipFile(ADDON) as addon:
            settings_hash = hashlib.sha256(addon.read(SETTINGS)).hexdigest()
        settings_file = root / 'Avadon2Chinese/font.ini'
        prefs = b'[Font]\r\nScalePercent=125\r\n'
        for prior_version in ('1.1', '1.2', '1.3', '1.4'):
            with zipfile.ZipFile(DISPATCH / f'{GAME_NAME}_子非鱼汉化{prior_version}.zip') as prior:
                prior.extractall(root)
                previous_files = {item['path']: item['sha256']
                                  for item in json.loads(prior.read('PATCH_MANIFEST.json'))['files']}
            install('install')
            assert_game(original | previous_files)
            with zipfile.ZipFile(ADDON) as addon:
                addon.extractall(root)
            settings_file.write_bytes(prefs)
            with zipfile.ZipFile(ARCHIVE) as archive:
                archive.extractall(root)
            install('install')
            assert_game(original | installed | {SETTINGS: settings_hash})
            if settings_file.read_bytes() != prefs:
                raise ValueError(f'Upgrade from {prior_version} discarded player preferences')
            install('uninstall')
            assert_game(original | {SETTINGS: settings_hash})
            (root / SETTINGS).unlink()
        with zipfile.ZipFile(PREVIOUS_ARCHIVE) as previous:
            previous.extractall(root)
            previous_manifest = json.loads(previous.read('PATCH_MANIFEST.json'))
            previous_files = {item['path']: item['sha256'] for item in previous_manifest['files']}
        install('install')
        assert_game(original | previous_files)
        legacy_addon = {SETTINGS: previous_files[SETTINGS]}
        settings_file.write_bytes(prefs)
        with zipfile.ZipFile(ARCHIVE) as archive:
            archive.extractall(root)
        install('install')
        assert_game(original | installed | legacy_addon)
        if settings_file.read_bytes() != prefs:
            raise ValueError('Reinstall discarded player preferences')
        install('install')
        assert_game(original | installed | legacy_addon)

        # Exercise the upgrade branch with a modified payload in the isolated replay only.
        staged.write_bytes(initial + b'\n')
        sample['sha256'] = sha(staged)
        sample['size'] = staged.stat().st_size
        save(root / 'PATCH_MANIFEST.json', manifest)
        install('install')
        assert_game(original | installed | legacy_addon | {sample['path']: sample['sha256']})
        install('uninstall')
        assert_game(original | legacy_addon)
        install('uninstall')
        assert_game(original | legacy_addon)
        with zipfile.ZipFile(ARCHIVE) as archive:
            archive.extractall(root)
        install('install')
        with zipfile.ZipFile(ADDON) as addon:
            addon_files = {SETTINGS, '体验优化说明.txt', '体验优化_SHA256SUMS.txt'}
            if (addon.testzip() is not None or set(addon.namelist()) != addon_files
                    or addon.read('体验优化_SHA256SUMS.txt').decode().split() != [settings_hash, SETTINGS]
                    or hashlib.sha256(addon.read(SETTINGS)).hexdigest() != settings_hash):
                raise ValueError('Invalid independent settings ZIP')
            addon.extractall(root)
        assert_game(original | installed | {SETTINGS: settings_hash})
        install('uninstall')
        assert_game(original | {SETTINGS: settings_hash})
    save(DISPATCH / 'RELEASE_VALIDATION.json', dict(
        status='passed', archive=ARCHIVE.name, sha256=sha(ARCHIVE), payload_files=len(installed),
        zip_crc=True, archive_hashes=True, installer_replay=['corrupt_payload', 'install',
            'direct_upgrade_from_v1.0_preserves_preferences', 'direct_upgrade_from_v1.1_preserves_addon',
            'direct_upgrade_from_v1.2_preserves_addon', 'direct_upgrade_from_v1.3_preserves_addon',
            'direct_upgrade_from_v1.4_preserves_addon',
            'repeat_install', 'upgrade', 'uninstall',
            'repeat_uninstall', 'optional_settings_preserved_on_base_uninstall'], game_started=False,
        optional_archive=ADDON.name, optional_sha256=sha(ADDON),
    ))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('build', 'verify'))
    options = parser.parse_args()
    payload, textures, installer = bindings()
    if options.action == 'build':
        accept(payload, textures)
        package(payload, installer)
    verify(payload, installer)
