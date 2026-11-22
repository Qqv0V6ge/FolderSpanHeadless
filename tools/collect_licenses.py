"""Collect Cargo dependency license texts without shipping dependency source trees."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]
def main(target, features=None):
    command = ["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", target]
    if features:
        command.extend(["--features", features])
    metadata = json.loads(subprocess.check_output(command, cwd=ROOT))
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    selected = set()
    root = metadata["resolve"]["root"]
    pending = [root]
    while pending:
        node = pending.pop()
        if node in selected:
            continue
        selected.add(node)
        pending.extend(dep["pkg"] for dep in nodes[node]["deps"] if any(kind["kind"] != "dev" for kind in dep["dep_kinds"]))
    output = ROOT / ".cache/third-party-licenses" / target
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    index = []
    for package in metadata["packages"]:
        if package["id"] not in selected or package["id"] == root:
            continue
        source = Path(package["manifest_path"]).parent
        dest = output / (package["name"] + "-" + package["version"])
        dest.mkdir(exist_ok=True)
        texts = []
        for path in sorted(source.rglob("*")):
            if path.is_file() and path.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE")):
                relative = path.relative_to(source)
                license_target = dest / relative
                license_target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, license_target)
                texts.append(relative.as_posix())
        if not texts and package["name"] == "yasna" and package["version"] == "0.5.2":
            # shortcut: yasna 0.5.2 omits separate license files; review this override when upgrading it.
            shutil.copy2(ROOT / "LICENSE", dest / "LICENSE-APACHE")
            notice = (source / "src/lib.rs").read_text().split("\n\n", 1)[0]
            (dest / "NOTICE").write_text(notice + "\n")
            texts = ["LICENSE-APACHE", "NOTICE"]
        if not texts and package["name"] == "selectors" and package["version"] == "0.41.0" and package["license"] == "MPL-2.0":
            # shortcut: selectors 0.41.0 omits its license file; review this fallback when upgrading.
            shutil.copy2(ROOT / "licenses/MPL-2.0.txt", dest / "LICENSE-MPL-2.0")
            notice = (source / "lib.rs").read_text().split("\n\n", 1)[0]
            revision = json.loads((source / ".cargo_vcs_info.json").read_text())["git"]["sha1"]
            notice += "\n\nUnmodified source: https://crates.io/api/v1/crates/selectors/0.41.0/download\n"
            notice += "Upstream revision: https://github.com/servo/stylo/tree/" + revision + "/selectors\n"
            (dest / "NOTICE").write_text(notice)
            texts = ["LICENSE-MPL-2.0", "NOTICE"]
        override = ROOT / "licenses" / (package["name"] + "-" + package["version"])
        if not texts and (override / "override.json").is_file():
            info = json.loads((override / "override.json").read_text())
            vcs = json.loads((source / ".cargo_vcs_info.json").read_text())["git"]
            if info["license"] != package["license"] or info["revision"] != vcs["sha1"] or info.get("dirty", False) != vcs.get("dirty", False):
                raise ValueError("License override must be reviewed for " + package["name"])
            if info.get("archiveSha256"):
                packages = tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]
                archive = next((p.get("checksum") for p in packages if p["name"] == package["name"] and p["version"] == package["version"]), None)
                if archive != info["archiveSha256"]:
                    raise ValueError("License archive changed for " + package["name"])
            if "NOTICE" not in info["files"] or not ({"LICENSE-MIT", "LICENSE-APACHE"} & info["files"].keys()):
                raise ValueError("License override is incomplete")
            for name, digest in info["files"].items():
                if name not in {"LICENSE-MIT", "LICENSE-APACHE", "NOTICE"} or hashlib.sha256((override / name).read_bytes()).hexdigest() != digest:
                    raise ValueError("License override changed for " + package["name"])
                shutil.copy2(override / name, dest / name)
                texts.append(name)
        if not texts:
            raise ValueError("License texts missing for " + package["name"])
        index.append({"name": package["name"], "version": package["version"], "license": package["license"], "texts": texts})
    (output / "index.json").write_text(json.dumps(index, indent=2) + "\n")
    files = {path.relative_to(output).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
             for path in output.rglob("*") if path.is_file()}
    manifest = {"version": 1, "target": target, "cargoLockSha256": hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest(), "files": files}
    (output / "bundle.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Collected licenses for {len(index)} packages")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--features")
    args = parser.parse_args()
    main(args.target, args.features)
