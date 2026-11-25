# 阿瓦登 2：腐化之地简体中文汉化工程

- 中文名：阿瓦登 2：腐化之地（暂译，沿用前作的地名译法）
- 开发商及发行商：Spiderweb Software
- 发行平台：本工程使用 Steam Windows 版，App ID 233310，Build ID 4512909，程序字符串 v1.0.1S，x86。Steam 发售日期为 2013-10-30。
- 原语言：英语。Steam 商店语言表列出英语界面。

面向汉化维护与二次开发。玩家可在 [GitHub Releases](https://github.com/zfyu222/avadon-2-the-corruption-hanhua/releases/) 获取补丁及安装说明，当前公开版本为 v1.5。

## 修改译文

- [正文译文](avadon-2_text_translated.csv)共 18,484 条，[正文映射](avadon-2_text.mapping.json)记录资源位置和原文 SHA-256。
- [贴图译文](avadon-2_images_text_translated.csv)共 79 条，[贴图映射](avadon-2_images_text.mapping.json)记录对应区域。按现有行序编辑单列 UTF-8 CSV，保留占位符和换行。
- [正文导出校验](TranslateFiles/reports/final_validation.json)记录当前正式译文的哈希。编辑后需重做对应验收，生成与新译文匹配的校验记录。
- [正文术语表](TranslateFiles/glossary/revision_6_b1979975/built/glossary_reviewed.json)和[贴图术语表](TranslateFiles/image-text/TranslateFiles/glossary/r2/freeze_ea1f1ddd/built/glossary_reviewed.json)供修改时查阅。

## 开发与构建

准备 Windows、Python 3.12 和 Visual Studio 的 x86 C++ 工具链。把本仓库克隆到 StaticHanHua 工作区的 `Projects/avadon-2/`，把[《阿瓦登：黑色要塞》工程](https://github.com/zfyu222/avadon-the-black-fortress-hanhua)克隆到同级的 `avadon-the-black-fortress/`。[共用工具](https://github.com/zfyu222/StaticHanHua/tree/master/Tools/localization)及[原生构建依赖说明](https://github.com/zfyu222/StaticHanHua/tree/master/Tools/native)位于工作区的 `Tools/`。MinHook v1.3.4（提交 `c3fcafdc10146beb5919319d0683e44e3c30d537`）放在 `Tools/native/MinHook/`。

把自己持有的 Steam Build 4512909 的原版文件放到项目 `Game/`，保持数据目录结构。已有汉化的安装请使用原版备份或干净副本。按[原件清单](Extraction/source_manifest.json)确认版本和文件哈希。下列命令均在项目根目录运行，输出到新的构建路径。

```powershell
python Extraction/restore_source_csv.py avadon-2_text.mapping.json Game
python Repack/stage_text.py --out Build/text-stage.json
python Repack/build_runtime.py --out Build/runtime
```

[原文恢复脚本](Extraction/restore_source_csv.py)按映射从本地原件恢复已绑定的单列原文 CSV，逐条检查哈希。[正文预检](Repack/stage_text.py)核对原始文件、映射和译文版本。[运行时构建器](Repack/build_runtime.py)生成运行时词典、转发模块及脚本/场景数据，原生适配代码位于 [Repack/native/adapter.cpp](Repack/native/adapter.cpp)。

[图片提取](Extraction/prepare_images.py)和[图片回填](Repack/stage_images.py)使用本机贴图。绘制时结合贴图映射和[地图接缝](ImageText/map_seam.json)，以成图目录作为回填输入。完整发布包还需生成相应版本的贴图、运行时目录和安装载荷。已发布的二进制和贴图成品可从 Releases 获取。

[发布包构建脚本](Release/build_release.py)按本地发布版本目录组合载荷，[体验优化构建](Release/build_enhancement.py)和[设置器源码](Repack/EnhancementSettings.cs)用于可选补丁。使用构建脚本前按其输入声明准备版本目录。
