"""Build a portable preview with bundled standard Web or an external Web UI."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import tomllib
import zipfile
from web_artifact import verify, ROOT

TARGETS = {
    "x86_64-unknown-linux-gnu": ("linux-x64", "elf", 62),
    "aarch64-unknown-linux-gnu": ("linux-arm64", "elf", 183),
    "x86_64-apple-darwin": ("macos-x64", "mach", 0x01000007),
    "aarch64-apple-darwin": ("macos-arm64", "mach", 0x0100000C),
    "x86_64-pc-windows-msvc": ("windows-x64", "pe", 0x8664),
    "aarch64-pc-windows-msvc": ("windows-arm64", "pe", 0xAA64),
}
def validate_binary(path, target):
    with path.open("rb") as stream:
        header = stream.read(4096)
    _, kind, machine = TARGETS[target]
    if kind == "elf":
        valid = header[:5] == b"\x7fELF\x02" and len(header) >= 20 and int.from_bytes(header[18:20], "little") == machine
    elif kind == "mach":
        valid = header[:4] == b"\xcf\xfa\xed\xfe" and int.from_bytes(header[4:8], "little") == machine
    else:
        offset = int.from_bytes(header[0x3c:0x40], "little")
        valid = header[:2] == b"MZ" and header[offset:offset+4] == b"PE\0\0" and int.from_bytes(header[offset+4:offset+6], "little") == machine
    if not valid:
        raise ValueError("Native binary architecture does not match target")

def verify_licenses(directory, target, cargo_lock):
    manifest_path = directory / "bundle.json"
    if not manifest_path.is_file():
        raise ValueError("Run tools/collect_licenses.py for the current lock and target")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("version") != 1 or manifest.get("target") != target or manifest.get("cargoLockSha256") != hashlib.sha256(cargo_lock.read_bytes()).hexdigest():
        raise ValueError("License bundle does not match Cargo.lock and target")
    files = manifest.get("files", {})
    actual = {path.relative_to(directory).as_posix() for path in directory.rglob("*") if path.is_file() and path != manifest_path}
    if not files or "index.json" not in files or set(files) != actual:
        raise ValueError("License bundle inventory mismatch")
    for relative, digest in files.items():
        path = directory / relative
        if Path(relative).is_absolute() or ".." in Path(relative).parts or path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("License bundle content mismatch")

def package(target, binary, web, destination, *, lock_path=None, edition="standard"):
    validate_binary(binary, target)
    lock_path = lock_path or ROOT / "upstream.lock.json"
    web_kind = "none"
    if web is not None:
        artifact = verify(web, json.loads(lock_path.read_text(encoding="utf-8")))
        if edition != "standard" or artifact.get("edition", "standard") != "standard":
            raise ValueError("Portable previews require standard Web; Pro uses an external directory")
        web_kind = artifact["kind"]
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
    web_suffix = "" if web_kind == "js" else f"-{web_kind}"
    edition_suffix = "-pro" if edition == "pro" else ""
    name = f"FolderSpanHeadless-{version}-{TARGETS[target][0]}{edition_suffix}{web_suffix}-preview"
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temp:
        stage = Path(temp) / name
        stage.mkdir()
        executable = "folderspan-headless" + (".exe" if "windows" in target else "")
        shutil.copy2(binary, stage / executable)
        if web is not None:
            shutil.copytree(web, stage / "web-ui")
        for file in ("LICENSE", "NOTICE", "Cargo.lock"):
            shutil.copy2(ROOT / file, stage / file)
        shutil.copy2(ROOT / "readme.md", stage / "README.md")
        shutil.copy2(lock_path, stage / "upstream.lock.json")
        licenses = ROOT / ".cache/third-party-licenses" / target
        verify_licenses(licenses, target, ROOT / "Cargo.lock")
        shutil.copytree(licenses, stage / "third-party-licenses")
        sums = []
        for file in sorted(stage.rglob("*")):
            if file.is_file():
                sums.append(f"{hashlib.sha256(file.read_bytes()).hexdigest()}  {file.relative_to(stage).as_posix()}")
        (stage / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8", newline="\n")
        if "windows" in target:
            output = destination / f"{name}.zip"
            with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, strict_timestamps=False) as archive:
                for file in sorted(stage.rglob("*")):
                    archive.write(file, file.relative_to(stage.parent))
        else:
            output = destination / f"{name}.tar.gz"
            with tarfile.open(output, "w:gz") as archive:
                archive.add(stage, arcname=name)
    checksum = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_name(output.name + ".sha256").write_text(f"{checksum}  {output.name}\n", newline="\n")
    return output

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target", required=True, choices=TARGETS)
    p.add_argument("--binary", type=Path)
    p.add_argument("--edition", choices=["standard", "pro"], default="standard")
    p.add_argument("--lock", type=Path, help="the Web lock for this build")
    web_options = p.add_mutually_exclusive_group()
    web_options.add_argument("--web-root", type=Path, default=ROOT / "web-ui",
                             help="verified standard JS or Wasm Web artifact")
    web_options.add_argument("--no-web-ui", action="store_true", help="omit bundled Web assets")
    p.add_argument("--output", type=Path, default=ROOT / "dist")
    a = p.parse_args()
    suffix = ".exe" if "windows" in a.target else ""
    binary = a.binary or ROOT / "target" / a.target / "release" / ("folderspan-headless" + suffix)
    print(package(a.target, binary, None if a.no_web_ui else a.web_root, a.output,
                  lock_path=a.lock, edition=a.edition))
