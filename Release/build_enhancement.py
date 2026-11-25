"""Build the independently versioned Avadon 2 enhancement patch."""

import hashlib
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import zipfile


PROJECT = Path(__file__).resolve().parents[1]
DISPATCH = PROJECT / 'Dispatch'
EXE = 'Enhancement-Settings.exe'
ARCHIVE = DISPATCH / '阿瓦登 2：腐化之地_体验优化1.1.zip'
GUIDE = """阿瓦登 2：腐化之地 · 体验优化补丁 1.1

可选，推荐使用。需要先安装 v1.1 或更新版汉化补丁。
解压到 Avadon 2.exe 所在目录，双击 Enhancement-Settings.exe 并保存设置。设置在下次启动游戏时生效。
升级时覆盖解压即可，已保存的设置会保留。

首次设置的默认值
界面语言跟随系统，中文字号 150%，探索移速 200%，可互动物体标记始终显示。
开启短标签适配、再次按快捷键关闭背包和镜头跟随。
"""


def main():
    if ARCHIVE.exists():
        raise FileExistsError(ARCHIVE)
    DISPATCH.mkdir(exist_ok=True)
    compiler = Path('C:/Windows/Microsoft.NET/Framework/v4.0.30319/csc.exe')
    with TemporaryDirectory(prefix='av2-enhancement-', dir=DISPATCH) as temporary:
        root = Path(temporary)
        executable = root / EXE
        subprocess.run([str(compiler), '/nologo', '/target:winexe', '/optimize+',
                        f'/out:{executable}', '/reference:System.Drawing.dll',
                        '/reference:System.Windows.Forms.dll', str(PROJECT / 'Repack/EnhancementSettings.cs')],
                       check=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
        program = executable.read_bytes()
        checksum = hashlib.sha256(program).hexdigest()
        ready = root / ARCHIVE.name
        with zipfile.ZipFile(ready, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(EXE, program)
            archive.writestr('体验优化说明.txt', GUIDE.replace('\n', '\r\n').encode('utf-8-sig'))
            archive.writestr('体验优化_SHA256SUMS.txt', f'{checksum}  {EXE}\n')
        with zipfile.ZipFile(ready) as archive:
            if archive.testzip() is not None or archive.read(EXE) != program:
                raise ValueError('Enhancement archive verification failed')
        ready.rename(ARCHIVE)
    print(ARCHIVE)


if __name__ == '__main__':
    main()
