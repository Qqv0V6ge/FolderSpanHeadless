"""Seal and verify an externally built, pinned FolderSpan Web distribution."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "folderspan-web-artifact.json"
LOCK_NAME = "upstream.lock.json"

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def inventory(root):
    files = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("Web artifacts cannot contain symbolic links")
        if path.is_file() and path != root / MANIFEST:
            files[path.relative_to(root).as_posix()] = digest(path)
    if "index.html" not in files:
        raise ValueError("Web artifact has no index.html")
    return files

def verify(root, lock):
    manifest = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
    if (manifest["upstreamCommit"] != lock["upstreamCommit"]
            or manifest["protocolVersion"] != lock.get("protocolVersion", 1)):
        raise ValueError("Web artifact does not match the pinned protocol/source")
    edition = manifest.get("edition", "standard")
    if edition == "pro":
        if not lock.get("proCommit") or manifest.get("proCommit") != lock["proCommit"]:
            raise ValueError("Web artifact does not match the pinned Pro source")
        pins = lock.get("proWeb", {})
    elif edition == "standard":
        pins = lock.get("web", {})
    else:
        raise ValueError("Unknown Web artifact edition")
    actual = inventory(root)
    if manifest["files"] != actual:
        raise ValueError("Web artifact checksum mismatch, missing or extra file")
    tree_hash = hashlib.sha256(json.dumps(actual, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    pin = pins.get(manifest["kind"])
    if not pin or pin["treeSha256"] != tree_hash or pin.get("fileCount", len(actual)) != len(actual):
        raise ValueError("Web artifact is not pinned in upstream.lock.json")
    return manifest

def seal(source, output, kind, edition="standard", *, lock_path=None,
         client_commit=None, pro_commit=None, host_commit=None, host_pro_commit=None):
    source = source.resolve()
    output = output.resolve()
    if source == output or source in output.parents or output in source.parents or output.exists():
        raise ValueError("Output must be a new directory outside the source")
    files = inventory(source)
    baseline_path = ROOT / LOCK_NAME
    lock_path = lock_path or baseline_path
    if client_commit is None:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    else:
        if lock_path.resolve() == baseline_path.resolve() or lock_path.exists():
            raise ValueError("A new client commit requires a new lock file")
        if not re.fullmatch(r"[0-9a-f]{40}", client_commit):
            raise ValueError("Client commit must be a full Git SHA")
        if host_commit is not None and not re.fullmatch(r"[0-9a-f]{40}", host_commit):
            raise ValueError("Host commit must be a full Git SHA")
        if edition == "pro" and not re.fullmatch(r"[0-9a-f]{40}", pro_commit or ""):
            raise ValueError("Pro commit must be a full Git SHA")
        if edition == "standard" and pro_commit is not None:
            raise ValueError("Standard Web cannot include a Pro commit")
        if host_pro_commit is not None:
            if edition != "pro" or not re.fullmatch(r"[0-9a-f]{40}", host_pro_commit):
                raise ValueError("A Headless Pro commit requires a Pro build and a full Git SHA")
            if host_commit is None:
                raise ValueError("A Headless Pro commit requires a public native host commit")
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        lock = {
            "upstreamCommit": client_commit,
            "protocolVersion": baseline["protocolVersion"],
            "specificationVersion": baseline["specificationVersion"],
        }
        if edition == "pro":
            lock["proCommit"] = pro_commit
        if host_commit is not None:
            lock["hostCommit"] = host_commit
        if host_pro_commit is not None:
            lock["headlessProCommit"] = host_pro_commit
    manifest = {"version": 1, "upstreamCommit": lock["upstreamCommit"],
                "protocolVersion": lock.get("protocolVersion", 1),
                "kind": kind, "edition": edition, "files": files}
    if edition == "pro":
        manifest["proCommit"] = lock["proCommit"]
    shutil.copytree(source, output)
    (output / MANIFEST).write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tree_hash = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    lock.setdefault("proWeb" if edition == "pro" else "web", {})[kind] = {
        "treeSha256": tree_hash, "fileCount": len(files)
    }
    verify(output, lock)
    lock_path.write_text(json.dumps(lock, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return tree_hash

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "web-ui")
    parser.add_argument("--kind", choices=["js", "wasm"], default="js")
    parser.add_argument("--edition", choices=["standard", "pro"], default="standard")
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--lock", type=Path)
    parser.add_argument("--client-commit", help="seal a CI build with a new lock file")
    parser.add_argument("--pro-commit", help="Pro submodule commit for a new Pro lock")
    parser.add_argument("--host-commit", help="native host commit for the build lock")
    parser.add_argument("--host-pro-commit", help="private native implementation commit for the build lock")
    args = parser.parse_args()
    if args.pro_commit and not args.client_commit:
        parser.error("--pro-commit requires --client-commit")
    if args.verify:
        lock = json.loads((args.lock or ROOT / LOCK_NAME).read_text(encoding="utf-8"))
        if args.host_commit and lock.get("hostCommit") != args.host_commit:
            parser.error("Web lock does not match the native host commit")
        if args.host_pro_commit and lock.get("headlessProCommit") != args.host_pro_commit:
            parser.error("Web lock does not match the native Pro implementation commit")
        verify(args.verify, lock)
        print("Web artifact verified")
    elif args.source:
        if (args.host_commit or args.host_pro_commit) and not args.client_commit:
            parser.error("Native host revisions require --client-commit when sealing")
        print(seal(args.source, args.output, args.kind, args.edition, lock_path=args.lock,
                   client_commit=args.client_commit, pro_commit=args.pro_commit,
                   host_commit=args.host_commit, host_pro_commit=args.host_pro_commit))
    else:
        parser.error("--source or --verify is required")
