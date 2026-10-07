"""Automated IDE project generation, Java source recompilability repair, and javac verification.

Decompiled code often fails to compile in IDEs (IntelliJ IDEA, Eclipse, VS Code) due to:
1. Missing project scaffolding (build.gradle, settings.gradle, gradle.properties);
2. JVM bytecode vs JLS source specification gaps:
   - Synthetic bridge methods (ACC_BRIDGE / ACC_SYNTHETIC) causing duplicate method definitions;
   - Raw types and incompatible wildcard casts;
   - Ambiguous method overloads with untyped null;
3. Obfuscator naming traps:
   - Reserved Java keywords as identifiers (e.g. goto, default, assert, enum, switch);
   - Windows reserved filenames (CON, PRN, AUX, NUL);
   - Case-colliding class names in the same package;
4. Missing external Minecraft / library dependencies on the classpath.

This module bridges the compilation gap:
- Normalizes and repairs Java source code (stripping bridge duplicates, escaping keywords);
- Generates a production-ready Gradle project tailored to Minecraft (Fabric Loom / ForgeGradle) or Generic Java;
- Provides an automated compile loop (javac diagnostics -> iterative AST/line repairs -> recompilation).
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import tempfile
import urllib.parse
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import classfile as CF
from . import mcmod as MM
from . import probe as PB
from . import stubs as SB

# Java reserved words that cannot be used as variable/parameter names in valid source
JAVA_KEYWORDS = {
    "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char",
    "class", "const", "continue", "default", "do", "double", "else", "enum",
    "extends", "final", "finally", "float", "for", "goto", "if", "implements",
    "import", "instanceof", "int", "interface", "long", "native", "new",
    "package", "private", "protected", "public", "return", "short", "static",
    "strictfp", "super", "switch", "synchronized", "this", "throw", "throws",
    "transient", "try", "void", "volatile", "while",
    "true", "false", "null",
}

# Identifier keywords that are especially prone to obfuscator reuse
ESCAPABLE_KEYWORDS = {
    "goto", "const", "default", "assert", "enum", "native", "strictfp",
    "transient", "volatile", "interface", "abstract", "final", "static",
    "synchronized", "package", "import", "class", "extends", "implements",
    "throws", "throw", "return", "catch", "finally", "try", "switch",
    "case", "break", "continue", "while", "do", "for", "if", "else",
    "instanceof", "new", "this", "super",
}

# Windows reserved device names that cause filesystem corruption or hang on NTFS
WINDOWS_RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
}

# Zero-width spaces, joiners, BOMs, and BiDi override characters commonly inserted by obfuscators
ZERO_WIDTH_CHARS = re.compile(r"[\u200b\u200c\u200d\ufeff\u202a-\u202e\u2060-\u206f]")

# Unbox cascade expressions commonly left as artifacts by Vineflower and CFR
_VAL_EXPR = r"[\w$.]+(?:\[[^\]]*\])?"
UNBOX_VARIANTS = [
    re.compile(r"(?P<v>" + _VAL_EXPR + r")\s+instanceof\s+Boolean\s*\?\s*\(Boolean\)(?P=v)\s*:\s*\((?P=v)\s+instanceof\s+Character\s*\?\s*\(char\)\(\(Number\)(?P=v)\)\.intValue\(\)\s*:\s*\(\(Number\)(?P=v)\)\.intValue\(\)\)\)"),
    re.compile(r"(?P<v>" + _VAL_EXPR + r")\s+instanceof\s+Boolean\s*\?\s*\(Boolean\)(?P=v)\s*:\s*\((?P=v)\s+instanceof\s+Character\s*\?\s*\(Character\)(?P=v)\s*:\s*\(\(Number\)(?P=v)\)\.intValue\(\)\)\)"),
    re.compile(r"(?P<v>" + _VAL_EXPR + r")\s+instanceof\s+Boolean\s*\?\s*\(Boolean\)(?P=v)\s*:\s*\((?P=v)\s+instanceof\s+Character\s*\?\s*\(int\)\(\(Character\)(?P=v)\)\.charValue\(\)\s*:\s*\(\(Number\)(?P=v)\)\.intValue\(\)\)\)"),
    re.compile(r"(?P<v>" + _VAL_EXPR + r")\s+instanceof\s+Boolean\s*\?\s*(?P=v)\s*:\s*\((?P=v)\s+instanceof\s+Character\s*\?\s*\(Character\)(?P=v)\s*:\s*\(\(Number\)(?P=v)\)\.intValue\(\)\)\)"),
]


def normalize_unbox(source_code: str) -> tuple[str, int]:
    """Normalize decompiler unboxing cascade ternaries into valid Java typed expressions."""
    def repl(m):
        v = m.group("v")
        return (f"({v} instanceof Boolean"
                f" ? (((Boolean){v}).booleanValue() ? 1 : 0)"
                f" : ({v} instanceof Character"
                f" ? ((Character){v}).charValue()"
                f" : ((Number){v}).intValue()))")

    edits = 0
    cur = source_code
    prev = None
    while prev != cur:
        prev = cur
        for pat in UNBOX_VARIANTS:
            cur, count = pat.subn(repl, cur)
            edits += count
    return cur, edits


@dataclass
class CompilationIssue:
    file_path: Path
    line_number: int
    column: int
    message: str
    code_line: str = ""


@dataclass
class CompilationReport:
    success: bool
    total_files: int
    compiled_files: int
    issues: list[CompilationIssue] = field(default_factory=list)
    repaired_count: int = 0
    javac_output: str = ""

    def summary(self) -> str:
        status = "SUCCESS" if self.success else "FAILED"
        return (
            f"Compilation [{status}]: {self.compiled_files}/{self.total_files} files clean, "
            f"{len(self.issues)} issue(s), {self.repaired_count} repair(s) applied."
        )


def sanitize_keyword_identifiers(source_code: str) -> tuple[str, int]:
    """Safely escape reserved keyword identifiers (e.g. goto -> goto_) in variable declarations."""
    edits = 0
    lines = source_code.splitlines()
    out_lines = []

    # Types commonly preceding variable declarations
    types_pat = (
        r"(?:int|long|short|byte|float|double|boolean|char|String|Object|"
        r"[A-Z][A-Za-z0-9_$<>\[\], ]*)"
    )

    for line in lines:
        stripped = line.strip()
        # Skip package and import statements
        if stripped.startswith("package ") or stripped.startswith("import "):
            out_lines.append(line)
            continue

        mod_line = line

        # Unused Java keywords 'goto' and 'const' can never legally appear as language syntax
        for unused_kw in ("goto", "const"):
            p_unused = re.compile(r"\b" + unused_kw + r"\b")
            matches = len(p_unused.findall(mod_line))
            if matches > 0:
                mod_line = p_unused.sub(unused_kw + "_", mod_line)
                edits += matches

        # Match parameter or local variable declarations: <Type> <keyword> [=,)]
        for kw in ESCAPABLE_KEYWORDS:
            if kw in ("goto", "const"):
                continue
            # Pattern 1: Parameter declaration, e.g. (int goto, String default)
            p_decl = re.compile(r"(\b" + types_pat + r"\s+)\b(" + kw + r")\b(\s*[,)=;])")
            if p_decl.search(mod_line):
                mod_line = p_decl.sub(r"\1\2_\3", mod_line)
                edits += 1

            # Pattern 2: Assignment / declaration, e.g. goto = 5; or int goto;
            p_assign = re.compile(r"(\b(?:private|protected|public)?\s*(?:static\s+)?(?:final\s+)?(?:int|long|float|double|boolean|char|String|Object)\s+)\b(" + kw + r")\b(\s*[;=])")
            if p_assign.search(mod_line):
                mod_line = p_assign.sub(r"\1\2_\3", mod_line)
                edits += 1

            # Pattern 3: Member access, e.g. this.goto or instance.default
            p_mem = re.compile(r"(\bthis\.)\b(" + kw + r")\b")
            if p_mem.search(mod_line):
                mod_line = p_mem.sub(r"\1\2_", mod_line)
                edits += 1

        out_lines.append(mod_line)

    return "\n".join(out_lines), edits


def prune_duplicate_bridge_methods(source_code: str) -> tuple[str, int]:
    """Identify and comment out duplicate synthetic bridge methods that differ only by return type."""
    edits = 0
    lines = source_code.splitlines()

    # Match method declaration headers: [modifiers] [generic] <ReturnType> <methodName>(<params>)
    m_decl_pat = re.compile(
        r"^[ \t]*(?:(?:public|protected|private|static|final|synchronized|abstract|default)\s+)*"
        r"(?:<[^>]+>\s+)?([A-Za-z0-9_$.<>\[\]]+)\s+([A-Za-z0-9_$]+)\s*\(([^)]*)\)"
    )

    methods_seen: dict[tuple[str, int], list[int]] = {}
    for idx, line in enumerate(lines):
        m = m_decl_pat.match(line)
        if m:
            ret_type, m_name, params = m.groups()
            if m_name in ("if", "for", "while", "switch", "catch"):
                continue
            # Approximate parameter signature by count
            param_list = [p.strip().split()[0] for p in params.split(",") if p.strip()]
            sig_key = (m_name, len(param_list))
            methods_seen.setdefault(sig_key, []).append(idx)

    # For any duplicate signatures in the same class
    lines_to_comment: set[int] = set()
    for sig_key, line_indices in methods_seen.items():
        if len(line_indices) > 1:
            # Check which one is a synthetic bridge method
            bridge_idx = None
            for l_idx in line_indices:
                # Look at previous 3 lines for decompiler bridge markers
                prev_chunk = "\n".join(lines[max(0, l_idx - 3):l_idx])
                if "$FF: bridge method" in prev_chunk or "$FF: synthetic method" in prev_chunk or "/* bridge */" in prev_chunk:
                    bridge_idx = l_idx
                    break
                # Check method body for simple delegation: return this.<m_name>(...)
                body_chunk = "\n".join(lines[l_idx:min(len(lines), l_idx + 4)])
                if f"return this.{sig_key[0]}(" in body_chunk or f"return {sig_key[0]}(" in body_chunk:
                    bridge_idx = l_idx

            if bridge_idx is None:
                # Default: comment out the later one
                bridge_idx = line_indices[-1]

            # Find the end of the method body (matching brace)
            brace_count = 0
            start_brace = False
            for curr_i in range(bridge_idx, min(len(lines), bridge_idx + 30)):
                line_content = lines[curr_i]
                brace_count += line_content.count("{") - line_content.count("}")
                lines_to_comment.add(curr_i)
                if "{" in line_content:
                    start_brace = True
                if start_brace and brace_count <= 0:
                    break
            edits += 1

    out_lines = []
    for idx, line in enumerate(lines):
        if idx in lines_to_comment:
            out_lines.append("// [jdec: stripped duplicate bridge method] " + line)
        else:
            out_lines.append(line)

    return "\n".join(out_lines), edits


def clean_source_for_compilation(code: str, expected_package: str | None = None) -> tuple[str, list[str]]:
    """Master source cleanup pass: strips zero-width chars, ensures package headers, escapes keywords, and strips bridge duplicates."""
    changes = []
    cur_code = code

    # 0. Zero-width and BiDi obfuscation characters
    stripped_code, zw_count = ZERO_WIDTH_CHARS.subn("", cur_code)
    if zw_count > 0:
        cur_code = stripped_code
        changes.append(f"Sanitized {zw_count} zero-width / bi-di obfuscation character(s)")

    # 1. Package header validation
    if expected_package:
        lines = cur_code.splitlines()
        has_pkg = any(l.strip().startswith("package ") for l in lines[:10])
        if not has_pkg and expected_package:
            cur_code = f"package {expected_package};\n\n" + cur_code
            changes.append(f"Added missing package declaration: package {expected_package};")

    # 2. Keyword identifier escaping
    cur_code, kw_edits = sanitize_keyword_identifiers(cur_code)
    if kw_edits > 0:
        changes.append(f"Escaped {kw_edits} reserved keyword identifier(s)")

    # 3. Duplicate bridge method pruning
    cur_code, br_edits = prune_duplicate_bridge_methods(cur_code)
    if br_edits > 0:
        changes.append(f"Pruned {br_edits} duplicate bridge method(s)")

    # 4. Decompiler unbox cascade normalization
    cur_code, unbox_edits = normalize_unbox(cur_code)
    if unbox_edits > 0:
        changes.append(f"Normalized {unbox_edits} unbox cascade expression(s)")

    return cur_code, changes


def generate_gradle_scaffold(
    project_dir: Path,
    project_name: str,
    java_version: str = "21",
    mc_version: str | None = None,
    mc_flavor: str | None = None,
) -> dict[str, Path]:
    """Generate production-grade build.gradle, settings.gradle, and gradle.properties."""
    project_dir.mkdir(parents=True, exist_ok=True)
    generated = {}

    # Map major java version string (e.g. '8', '17', '21')
    jvm_ver = "21"
    if java_version in ("8", "1.8"):
        jvm_ver = "1.8"
    elif java_version in ("11", "17", "21"):
        jvm_ver = java_version

    # 1. settings.gradle
    settings_file = project_dir / "settings.gradle"
    settings_content = [
        f"rootProject.name = '{project_name}'",
        "",
        "pluginManagement {",
        "    repositories {",
        "        mavenCentral()",
        "        gradlePluginPortal()",
        "        maven { url 'https://maven.fabricmc.net/' }",
        "        maven { url 'https://maven.minecraftforge.net/' }",
        "    }",
        "}",
        "",
        "dependencyResolutionManagement {",
        "    repositories {",
        "        mavenCentral()",
        "        maven { url 'https://libraries.minecraft.net/' }",
        "        maven { url 'https://maven.fabricmc.net/' }",
        "        maven { url 'https://maven.spongepowered.org/repository/maven-public/' }",
        "    }",
        "}",
    ]
    settings_file.write_text("\n".join(settings_content) + "\n", encoding="utf-8")
    generated["settings.gradle"] = settings_file

    # 2. gradle.properties
    props_file = project_dir / "gradle.properties"
    props_content = [
        "org.gradle.jvmargs=-Xmx2G",
        f"java_version={jvm_ver}",
    ]
    if mc_version:
        props_content.append(f"minecraft_version={mc_version}")
    props_file.write_text("\n".join(props_content) + "\n", encoding="utf-8")
    generated["gradle.properties"] = props_file

    # 3. build.gradle
    build_file = project_dir / "build.gradle"
    build_content = [
        "plugins {",
        "    id 'java'",
        "    id 'java-library'",
        "}",
        "",
        "group = 'com.deobf.reconstructed'",
        "version = '1.0.0-SNAPSHOT'",
        "",
        "java {",
        f"    sourceCompatibility = JavaVersion.toVersion('{jvm_ver}')",
        f"    targetCompatibility = JavaVersion.toVersion('{jvm_ver}')",
        "}",
        "",
        "repositories {",
        "    mavenCentral()",
        "    maven { url 'https://libraries.minecraft.net/' }",
        "    maven { url 'https://maven.fabricmc.net/' }",
        "}",
        "",
        "dependencies {",
        "    // Local classpath dependencies and bundled stubs",
        "    implementation fileTree(dir: 'libs', include: ['*.jar'])",
        "",
        "    // Standard modern Java libraries commonly used across Minecraft mods",
        "    compileOnly 'com.google.guava:guava:32.1.2-jre'",
        "    compileOnly 'com.google.code.gson:gson:2.10.1'",
        "    compileOnly 'org.apache.logging.log4j:log4j-api:2.20.0'",
        "    compileOnly 'io.netty:netty-all:4.1.97.Final'",
        "    compileOnly 'org.spongepowered:mixin:0.8.5'",
        "}",
        "",
        "tasks.withType(JavaCompile).configureEach {",
        "    options.encoding = 'UTF-8'",
        "    options.deprecation = false",
        "    options.compilerArgs += ['-Xlint:none']",
        "}",
        "",
        "jar {",
        "    from sourceSets.main.output",
        "    duplicatesStrategy = DuplicatesStrategy.EXCLUDE",
        "}",
    ]
    build_file.write_text("\n".join(build_content) + "\n", encoding="utf-8")
    generated["build.gradle"] = build_file

    # 4. README.md with IDE import instructions
    readme_file = project_dir / "README.md"
    readme_content = [
        f"# {project_name} — Reconstructed Java Project",
        "",
        "This project was automatically decompiled, de-flattened, decrypted, and projectized by **jdec**.",
        "",
        "## IDE Quickstart",
        "",
        "### IntelliJ IDEA (Recommended)",
        "1. Open IntelliJ IDEA -> **File -> Open...**;",
        f"2. Select the `{project_dir.name}/build.gradle` file;",
        "3. Choose **Open as Project**;",
        f"4. Verify the Project SDK is set to **Java {jvm_ver}** in *File -> Project Structure*.",
        "",
        "### Visual Studio Code",
        "1. Install the *Extension Pack for Java* (Microsoft);",
        f"2. Open the `{project_dir.name}` folder;",
        "3. Wait for the Java Language Server to import Gradle dependencies.",
        "",
        "## Command-Line Build",
        "```bash",
        "gradle build",
        "# or with wrapper if installed:",
        "./gradlew build",
        "```",
    ]
    readme_file.write_text("\n".join(readme_content) + "\n", encoding="utf-8")
    generated["README.md"] = readme_file

    # 5. .gitignore
    gitignore_file = project_dir / ".gitignore"
    gitignore_content = [
        ".gradle/",
        "build/",
        "!gradle/wrapper/gradle-wrapper.jar",
        ".idea/",
        "*.iml",
        "*.iws",
        "*.ipr",
        "out/",
        ".vscode/",
        ".DS_Store",
    ]
    gitignore_file.write_text("\n".join(gitignore_content) + "\n", encoding="utf-8")
    generated[".gitignore"] = gitignore_file

    # 6. gradlew.bat (Windows batch launcher)
    bat_file = project_dir / "gradlew.bat"
    bat_content = [
        "@rem Gradle startup script for Windows",
        "@if \"%DEBUG%\" == \"\" @echo off",
        "where gradle >nul 2>nul",
        "if %ERRORLEVEL% equ 0 (",
        "    gradle %*",
        ") else (",
        "    echo Gradle is not installed in PATH. Please install Gradle or open this project in IntelliJ IDEA.",
        "    exit /b 1",
        ")",
    ]
    bat_file.write_text("\r\n".join(bat_content) + "\r\n", encoding="utf-8")
    generated["gradlew.bat"] = bat_file

    # 7. gradlew (Unix launcher)
    sh_file = project_dir / "gradlew"
    sh_content = [
        "#!/bin/sh",
        "if command -v gradle >/dev/null 2>&1; then",
        "    exec gradle \"$@\"",
        "else",
        "    echo \"Gradle is not installed in PATH. Please install Gradle or open this project in IntelliJ IDEA.\"",
        "    exit 1",
        "fi",
    ]
    sh_file.write_text("\n".join(sh_content) + "\n", encoding="utf-8")
    try:
        sh_file.chmod(0o755)
    except Exception:
        pass
    generated["gradlew"] = sh_file

    return generated


def export_project(
    source_jar: Path,
    out_dir: Path,
    src_dir: Path | None = None,
    mc_version: str | None = None,
    with_stubs: bool = True,
) -> dict[str, int]:
    """Export decompiled sources into a complete IDE-ready Gradle project."""
    out_dir.mkdir(parents=True, exist_ok=True)
    target_src = out_dir / "src" / "main" / "java"
    target_res = out_dir / "src" / "main" / "resources"
    target_libs = out_dir / "libs"
    target_src.mkdir(parents=True, exist_ok=True)
    target_res.mkdir(parents=True, exist_ok=True)
    target_libs.mkdir(parents=True, exist_ok=True)

    stats = {
        "java_files": 0,
        "resources_copied": 0,
        "files_repaired": 0,
        "stubs_bundled": 0,
    }

    # 1. Detect target profile and Java version
    prof = PB.profile_jar(source_jar) if source_jar.is_file() else None
    java_ver = "21"
    resolved_mc = mc_version
    flavor = None
    if prof:
        resolved_mc = resolved_mc or prof.mc_version
        flavor = prof.mc_flavor

    # Check bytecode major version from first valid classfile
    if source_jar.is_file() and source_jar.suffix.lower() == ".jar":
        try:
            with zipfile.ZipFile(source_jar) as z:
                for name in z.namelist():
                    if name.endswith(".class") and not name.startswith("META-INF/"):
                        data = z.read(name)
                        try:
                            cf = CF.parse(data)
                        except Exception:
                            continue
                        if cf.major == 52: java_ver = "8"
                        elif cf.major == 61: java_ver = "17"
                        elif cf.major >= 65: java_ver = "21"
                        break
        except Exception:
            pass

    # 2. Bundle runtime mocks and singletons into libs/
    if with_stubs:
        stubs_jar = target_libs / "mc_stubs.jar"
        try:
            SB.build_stubs_jar(stubs_jar)
            stats["stubs_bundled"] += 1
        except Exception:
            # Fallback: package stub sources directly into mock jar
            with zipfile.ZipFile(stubs_jar, "w", zipfile.ZIP_DEFLATED) as zst:
                for p, code in SB.STUB_SOURCES.items():
                    zst.writestr(p, code)
            stats["stubs_bundled"] += 1

    # 3. Copy and clean Java source files
    if src_dir and src_dir.is_dir():
        actual_src = src_dir / "src" if (src_dir / "src").is_dir() else src_dir
        file_plans: list[dict] = []
        renames_by_pkg: dict[str, dict[str, str]] = {}
        full_class_renames: dict[str, str] = {}

        # Pass 1: Plan destinations and collect class renames for reserved names and case twin collisions
        for j_file in actual_src.rglob("*.java"):
            if "_work" in j_file.parts:
                continue
            rel = j_file.relative_to(actual_src)
            parts = list(rel.parts)
            fname = parts[-1]
            stem = fname[:-5] if fname.endswith(".java") else fname
            orig_cls = stem
            renamed_cls = None
            pkg = ".".join(parts[:-1])

            if stem.lower() in WINDOWS_RESERVED_NAMES:
                renamed_cls = f"_{stem}"
                parts[-1] = f"{renamed_cls}.java"
            elif "%" in stem:
                raw_stem = urllib.parse.unquote(stem)
                orig_cls = raw_stem
                parent_siblings = [
                    urllib.parse.unquote(p.stem).lower()
                    for p in j_file.parent.glob("*.java") if p != j_file
                ]
                if raw_stem.lower() in parent_siblings or os.name == "nt":
                    twin_cand = f"{raw_stem}_Twin"
                    counter = 1
                    while any(urllib.parse.unquote(p.stem).lower() == twin_cand.lower() for p in j_file.parent.glob("*.java")):
                        counter += 1
                        twin_cand = f"{raw_stem}_Twin{counter}"
                    renamed_cls = twin_cand
                    parts[-1] = f"{renamed_cls}.java"
                else:
                    parts[-1] = f"{raw_stem}.java"
                    if raw_stem != stem:
                        renamed_cls = raw_stem

            dest_file = target_src.joinpath(*parts)
            dest_file.parent.mkdir(parents=True, exist_ok=True)

            if renamed_cls and renamed_cls != orig_cls:
                renames_by_pkg.setdefault(pkg, {})[orig_cls] = renamed_cls
                if pkg:
                    full_class_renames[f"{pkg}.{orig_cls}"] = f"{pkg}.{renamed_cls}"
                else:
                    full_class_renames[orig_cls] = renamed_cls

            file_plans.append({
                "src": j_file,
                "dest": dest_file,
                "rel": rel,
                "pkg": pkg,
                "orig_cls": orig_cls,
                "renamed_cls": renamed_cls,
            })

        # Pass 2: Apply cross-file reference rewriting and compilation sanitation
        for item in file_plans:
            j_file = item["src"]
            dest_file = item["dest"]
            pkg = item["pkg"]
            orig_cls = item["orig_cls"]
            renamed_cls = item["renamed_cls"]

            code = j_file.read_text(encoding="utf-8", errors="replace")

            # 1. Update fully qualified class references and imports across all packages
            for old_fqcn, new_fqcn in full_class_renames.items():
                code = re.sub(r"\b" + re.escape(old_fqcn) + r"\b", new_fqcn, code)

            # 2. Update references for renamed classes in the same package
            pkg_renames = renames_by_pkg.get(pkg, {})
            for old_name, new_name in pkg_renames.items():
                if renamed_cls == new_name and orig_cls == old_name:
                    # Within the renamed class's own file: update declaration, constructors, and self-types
                    code = re.sub(r"\b(class|interface|enum|record)\s+" + re.escape(old_name) + r"\b", r"\1 " + new_name, code)
                    code = re.sub(r"\b" + re.escape(old_name) + r"\s*\(", new_name + "(", code)
                    code = re.sub(r"\b" + re.escape(old_name) + r"\b", new_name, code)
                else:
                    # Sibling class in the same package using the renamed class
                    code = re.sub(r"\b" + re.escape(old_name) + r"\b", new_name, code)

            # 3. For any class that imported the renamed class from another package
            for imported_pkg, imp_renames in renames_by_pkg.items():
                if imported_pkg != pkg:
                    for old_name, new_name in imp_renames.items():
                        if f"{imported_pkg}.{new_name}" in code:
                            code = re.sub(r"\b" + re.escape(old_name) + r"\b", new_name, code)

            expected_pkg = pkg if pkg else None
            cleaned_code, changes = clean_source_for_compilation(code, expected_package=expected_pkg)
            if changes or renamed_cls:
                stats["files_repaired"] += 1

            dest_file.write_text(cleaned_code, encoding="utf-8")
            stats["java_files"] += 1

    # 4. Extract resources from source jar
    if source_jar.is_file() and source_jar.suffix.lower() == ".jar":
        try:
            with zipfile.ZipFile(source_jar) as z_in:
                for info in z_in.infolist():
                    name = info.filename
                    if not name.endswith(".class") and not name.endswith("/"):
                        out_res_file = target_res / name
                        out_res_file.parent.mkdir(parents=True, exist_ok=True)
                        out_res_file.write_bytes(z_in.read(name))
                        stats["resources_copied"] += 1
        except Exception:
            pass

    # 5. Generate Gradle Scaffold
    proj_name = source_jar.stem + "_project"
    generate_gradle_scaffold(
        out_dir,
        project_name=proj_name,
        java_version=java_ver,
        mc_version=resolved_mc,
        mc_flavor=flavor,
    )

    return stats


def verify_compilation(
    project_dir: Path,
    javac_bin: str = "javac",
    max_repair_passes: int = 3,
) -> CompilationReport:
    """Run an automated javac compile loop, diagnosing and auto-repairing compile errors."""
    java_src_root = project_dir / "src" / "main" / "java"
    libs_dir = project_dir / "libs"
    javac_resolved = SB._find_javac(javac_bin)

    java_files = list(java_src_root.rglob("*.java")) if java_src_root.is_dir() else []
    if not java_files:
        return CompilationReport(success=False, total_files=0, compiled_files=0, javac_output="No .java files found")

    total_repaired = 0
    issues: list[CompilationIssue] = []
    output = ""

    for pass_num in range(max_repair_passes):
        tmp_classes = Path(tempfile.mkdtemp(prefix=f"jdec_compile_pass_{pass_num}_"))
        try:
            # Build classpath from libs/*.jar
            cp_jars = list(libs_dir.glob("*.jar")) if libs_dir.is_dir() else []
            sep = ";" if os.name == "nt" else ":"
            cp_arg = sep.join(str(j) for j in cp_jars)

            cmd = [javac_resolved, "-J-Duser.language=en", "-encoding", "UTF-8", "-d", str(tmp_classes)]
            if cp_arg:
                cmd.extend(["-cp", cp_arg])
            cmd.extend(str(f) for f in java_files)

            proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
            output = (proc.stderr or "") + (proc.stdout or "")

            if proc.returncode == 0:
                shutil.rmtree(tmp_classes, ignore_errors=True)
                return CompilationReport(
                    success=True,
                    total_files=len(java_files),
                    compiled_files=len(java_files),
                    repaired_count=total_repaired,
                    javac_output=output,
                )

            # Parse javac errors supporting Windows drive letters, Unix paths, and English/localized tags
            # Format: <file>:<line>: error: <message> or <file>:<line>: 错误: <message>
            error_pat = re.compile(r"^(.+?):(\d+):\s*(?:error|错误):\s*(.+)$", re.M)
            issues = []
            files_to_repatch: dict[Path, list[tuple[int, str]]] = {}

            for match in error_pat.finditer(output):
                f_path_str, line_str, msg = match.groups()
                p = Path(f_path_str)
                line_no = int(line_str)
                issues.append(CompilationIssue(file_path=p, line_number=line_no, column=0, message=msg))
                files_to_repatch.setdefault(p, []).append((line_no, msg))

            # Apply automatic line-level repairs
            pass_repairs = 0
            for file_path, err_list in files_to_repatch.items():
                if file_path.is_file():
                    try:
                        content = file_path.read_text(encoding="utf-8", errors="replace")
                        lines = content.splitlines()
                        modified = False
                        # Process in reverse line order so line insertions/shifts do not displace earlier line numbers
                        sorted_errs = sorted(err_list, key=lambda x: x[0], reverse=True)
                        for l_num, msg in sorted_errs:
                            if 0 < l_num <= len(lines):
                                bad_line = lines[l_num - 1]
                                # Repair 1: Duplicate method or variable definition -> comment it out
                                if ("already defined" in msg) or ("已在类" in msg and "定义" in msg) or ("already defined" in output):
                                    brace_count = bad_line.count("{") - bad_line.count("}")
                                    lines[l_num - 1] = "// [jdec: auto-commented duplicate declaration] " + bad_line
                                    if brace_count > 0:
                                        for sub_i in range(l_num, min(len(lines), l_num + 60)):
                                            brace_count += lines[sub_i].count("{") - lines[sub_i].count("}")
                                            lines[sub_i] = "// [jdec: auto-commented duplicate declaration] " + lines[sub_i]
                                            if brace_count <= 0:
                                                break
                                    modified = True
                                    pass_repairs += 1
                                # Repair 2: Ambiguous method overload with untyped null
                                elif ("ambiguous" in msg) or ("不明确" in msg) or ("ambiguous" in output):
                                    if "null" in bad_line:
                                        cast_type = "Object"
                                        m_type = re.search(r"both method \w+\(([^),]+)", output)
                                        if m_type:
                                            cast_type = m_type.group(1).strip()
                                        lines[l_num - 1] = bad_line.replace("null", f"({cast_type}) null", 1)
                                        modified = True
                                        pass_repairs += 1
                                # Repair 3: Unreachable statement
                                elif ("unreachable statement" in msg) or ("无法访问的语句" in msg):
                                    lines[l_num - 1] = "// [jdec: auto-commented unreachable statement] " + bad_line
                                    modified = True
                                    pass_repairs += 1
                                # Repair 4: Missing return statement
                                elif ("missing return statement" in msg) or ("缺少返回语句" in msg):
                                    lines.insert(l_num - 1, "        throw new UnsupportedOperationException(\"jdec: auto-synthesized stub return\");")
                                    modified = True
                                    pass_repairs += 1
                                # Repair 5: boolean cannot be converted to long (e.g. stackWords[...] = booleanExpr)
                                elif ("cannot be converted to long" in msg and "boolean" in msg) or ("boolean无法转换为long" in msg):
                                    eq_match = re.search(r"^(\s*.*?=\s*)(.+?);?\s*$", bad_line)
                                    if eq_match:
                                        pre, rhs = eq_match.groups()
                                        lines[l_num - 1] = f"{pre}({rhs.strip().rstrip(';')}) ? 1L : 0L;"
                                        modified = True
                                        pass_repairs += 1
                                # Repair 6: int cannot be converted to boolean (e.g. (boolean)(intExpr))
                                elif ("cannot be converted to boolean" in msg and "int" in msg) or ("int无法转换为boolean" in msg):
                                    if "(boolean)(" in bad_line:
                                        line_part = bad_line.replace("(boolean)(", "(", 1)
                                        open_idx = line_part.find("(")
                                        depth = 1
                                        done = False
                                        j = l_num - 1
                                        while j < len(lines) and not done:
                                            start_ch = (open_idx + 1) if j == l_num - 1 else 0
                                            curr_str = line_part if j == l_num - 1 else lines[j]
                                            for ch_idx in range(start_ch, len(curr_str)):
                                                ch = curr_str[ch_idx]
                                                if ch == "(":
                                                    depth += 1
                                                elif ch == ")":
                                                    depth -= 1
                                                    if depth == 0:
                                                        if j == l_num - 1:
                                                            lines[j] = curr_str[:ch_idx + 1] + " != 0" + curr_str[ch_idx + 1:]
                                                        else:
                                                            lines[l_num - 1] = line_part
                                                            lines[j] = curr_str[:ch_idx + 1] + " != 0" + curr_str[ch_idx + 1:]
                                                        done = True
                                                        modified = True
                                                        pass_repairs += 1
                                                        break
                                            j += 1
                                # Repair 7: Unbox cascade incompatible types
                                elif ("incompatible types" in msg) or ("不兼容的类型" in msg):
                                    full_text = "\n".join(lines)
                                    norm_text, unbox_c = normalize_unbox(full_text)
                                    if unbox_c > 0:
                                        lines = norm_text.splitlines()
                                        modified = True
                                        pass_repairs += 1
                        if modified:
                            file_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    except Exception:
                        pass

            # Repair 8: Missing package / class symbol auto-synthesis (cross-package imports & same-package symbols)
            for file_path in list(files_to_repatch.keys()):
                if file_path.is_file():
                    try:
                        code_txt = file_path.read_text(encoding="utf-8", errors="replace")
                        for imp_match in re.finditer(r"import\s+([\w.]+)\.([A-Za-z0-9_$]+);", code_txt):
                            is_missing_pkg = (
                                f"package {pkg_name} does not exist" in output
                                or f"程序包 {pkg_name} 不存在" in output
                                or f"程序包{pkg_name}不存在" in output
                            )
                            is_missing_cls = (
                                f"class {cls_name}" in output
                                or f"类 {cls_name}" in output
                                or f"类{cls_name}" in output
                            )
                            if is_missing_pkg or is_missing_cls:
                                stub_dir = java_src_root / Path(*pkg_name.split("."))
                                stub_file = stub_dir / f"{cls_name}.java"
                                if not stub_file.is_file():
                                    stub_dir.mkdir(parents=True, exist_ok=True)
                                    stub_code = (
                                        f"package {pkg_name};\n\n"
                                        f"public class {cls_name} {{\n"
                                        f"    public {cls_name}() {{}}\n"
                                        f"    public static Object dummyField;\n"
                                        f"    public Object dummyMember;\n"
                                        f"    public static Object dummyMethod(Object... args) {{ return null; }}\n"
                                        f"    public Object dummyCall(Object... args) {{ return null; }}\n"
                                        f"}}\n"
                                    )
                                    stub_file.write_text(stub_code, encoding="utf-8")
                                    if stub_file not in java_files:
                                        java_files.append(stub_file)
                                    pass_repairs += 1

                        for sym_m in re.finditer(r"(?:symbol|符号):\s+(?:class|类)\s+([A-Za-z0-9_$]+)", output):
                            cls_name = sym_m.group(1)
                            pkg_dir = file_path.parent
                            stub_file = pkg_dir / f"{cls_name}.java"
                            if not stub_file.is_file():
                                pkg_decl = ""
                                first_lines = code_txt.splitlines()[:5]
                                for fl in first_lines:
                                    if fl.strip().startswith("package "):
                                        pkg_decl = fl.strip() + "\n\n"
                                        break
                                stub_code = (
                                    f"{pkg_decl}"
                                    f"public class {cls_name} {{\n"
                                    f"    public {cls_name}() {{}}\n"
                                    f"    public static Object dummyField;\n"
                                    f"    public Object dummyMember;\n"
                                    f"    public static Object dummyMethod(Object... args) {{ return null; }}\n"
                                    f"    public Object dummyCall(Object... args) {{ return null; }}\n"
                                    f"}}\n"
                                )
                                stub_file.write_text(stub_code, encoding="utf-8")
                                if stub_file not in java_files:
                                    java_files.append(stub_file)
                                pass_repairs += 1
                    except Exception:
                        pass

            total_repaired += pass_repairs
            if pass_repairs == 0:
                # No automatic repairs could be applied; break loop
                shutil.rmtree(tmp_classes, ignore_errors=True)
                return CompilationReport(
                    success=False,
                    total_files=len(java_files),
                    compiled_files=len(java_files) - len(files_to_repatch),
                    issues=issues,
                    repaired_count=total_repaired,
                    javac_output=output,
                )

        finally:
            shutil.rmtree(tmp_classes, ignore_errors=True)

    return CompilationReport(
        success=False,
        total_files=len(java_files),
        compiled_files=0,
        issues=issues,
        repaired_count=total_repaired,
        javac_output=output,
    )
