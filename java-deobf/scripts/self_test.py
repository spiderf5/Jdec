#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""校验 fingerprints.json 与 deobf_scan 的配置加载是否正常。

每次编辑 fingerprints.json 之后跑一次：
    python self_test.py [可选的 jar/class 路径]

不带参数时只校验配置；带 jar/class 路径时额外验证扫描能正常跑完。
退出码: 0 = 通过；1 = 有问题。
"""

import json
import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent))
import deobf_scan  # noqa: E402

REQUIRED_THRESHOLDS = [
    "min_instructions_for_flow_check", "goto_density_high", "switch_density_high",
    "goto_density_with_switch", "exception_ratio_high", "member_ratio_high",
    "encrypted_like_high", "indy_encoded_min",
]


def check(errors):
    path = deobf_scan.CONFIG_PATH
    if not path.is_file():
        errors.append("找不到 %s（脚本会回退到内置默认配置，但外部维护能力会失效）" % path.name)
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        errors.append("JSON 语法错误：%s" % exc)
        return
    if not isinstance(data, dict):
        errors.append("顶层必须是一个对象")
        return

    obfs = data.get("obfuscators")
    if not isinstance(obfs, list) or not obfs:
        errors.append("obfuscators 必须是非空数组")
    else:
        for i, item in enumerate(obfs):
            if not isinstance(item, dict):
                errors.append("obfuscators[%d] 不是对象" % i)
                continue
            for key in ("name", "keywords", "tool"):
                if not item.get(key):
                    errors.append("obfuscators[%d] 缺少 %s" % (i, key))
            if isinstance(item.get("keywords"), list) and not item["keywords"]:
                errors.append("obfuscators[%d].keywords 是空数组，等于永不命中" % i)

    for key in ("html_markers", "normal_bootstrap", "native_lib_exts"):
        if not data.get(key):
            errors.append("%s 缺失或为空" % key)

    thresholds = data.get("thresholds")
    if not isinstance(thresholds, dict):
        errors.append("thresholds 必须是一个对象")
    else:
        for key in REQUIRED_THRESHOLDS:
            if key not in thresholds:
                errors.append("thresholds 缺少 %s" % key)
            elif not isinstance(thresholds[key], (int, float)) or isinstance(thresholds[key], bool):
                errors.append("thresholds.%s 必须是数字" % key)

    # 实际加载后的状态
    if not deobf_scan.OBFUSCATOR_SIGNATURES:
        errors.append("加载后的混淆器表为空")
    if len(deobf_scan.OBFUSCATOR_SIGNATURES) != len(obfs or []):
        errors.append("加载后的混淆器条数与配置不一致（%d vs %d）"
                      % (len(deobf_scan.OBFUSCATOR_SIGNATURES), len(obfs or [])))
    for key in REQUIRED_THRESHOLDS:
        if key not in deobf_scan.THRESHOLDS:
            errors.append("运行时的 THRESHOLDS 缺少 %s" % key)


def scan_smoke(target):
    errors = []
    collected = deobf_scan.collect_classes(Path(target), 50)
    if not collected:
        errors.append("目标无法读取：%s" % target)
        return errors
    classes, cov = collected
    if not classes:
        errors.append("目标里没有可解析的 class：%s" % target)
        return errors
    info = deobf_scan.analyze(target, classes)
    for key in ("code_metrics", "strings", "naming", "recommendations"):
        if key not in info:
            errors.append("扫描结果缺少字段 %s" % key)
    return errors


def main():
    errors = []
    check(errors)
    if len(sys.argv) > 1:
        errors.extend(scan_smoke(sys.argv[1]))

    if errors:
        print("自测未通过：")
        for e in errors:
            print("  - %s" % e)
        return 1
    print("自测通过：配置已加载 %d 个混淆器指纹，%d 项阈值就绪。"
          % (len(deobf_scan.OBFUSCATOR_SIGNATURES), len(deobf_scan.THRESHOLDS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
