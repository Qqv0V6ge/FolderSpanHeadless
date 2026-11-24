import hashlib
import importlib.util
import json
import os
import zipfile
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import web_artifact
import collect_licenses
spec = importlib.util.spec_from_file_location("portable_package", Path(__file__).resolve().parents[1] / "tools/package.py")
portable = importlib.util.module_from_spec(spec)
spec.loader.exec_module(portable)

class ArtifactTests(unittest.TestCase):
    def test_ci_lock_records_the_client_build_without_rewriting_the_baseline(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            (source / "index.html").write_text("standard fixture")
            baseline = {"upstreamCommit": "old", "proCommit": "private",
                        "protocolVersion": 1, "specificationVersion": 4}
            (root / "upstream.lock.json").write_text(json.dumps(baseline))
            build_lock = root / "ci-lock.json"
            artifact = root / "sealed"
            with patch.object(web_artifact, "ROOT", root):
                web_artifact.seal(source, artifact, "wasm", lock_path=build_lock,
                                  client_commit="a" * 40, host_commit="b" * 40)
            lock = json.loads(build_lock.read_text())
            self.assertEqual(lock["upstreamCommit"], "a" * 40)
            self.assertEqual(lock["hostCommit"], "b" * 40)
            self.assertEqual(lock["specificationVersion"], 4)
            self.assertNotIn("proCommit", lock)
            self.assertNotIn("headlessProCommit", lock)
            self.assertEqual(web_artifact.verify(artifact, lock)["kind"], "wasm")
            self.assertEqual(json.loads((root / "upstream.lock.json").read_text()), baseline)

    def test_pro_artifact_has_an_independent_revision_and_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            (source / "index.html").write_text("pro fixture")
            lock = {"upstreamCommit": "upstream", "proCommit": "pro", "web": {}}
            lock_path = root / "upstream.lock.json"
            lock_path.write_text(json.dumps(lock))
            artifact = root / "sealed-pro"
            with patch.object(web_artifact, "ROOT", root):
                web_artifact.seal(source, artifact, "js", "pro")
            lock = json.loads(lock_path.read_text())
            self.assertEqual(lock["web"], {})
            self.assertEqual(web_artifact.verify(artifact, lock)["proCommit"], "pro")
            with self.assertRaisesRegex(ValueError, "pinned Pro source"):
                web_artifact.verify(artifact, dict(lock, proCommit="other"))
            with self.assertRaisesRegex(ValueError, "not pinned"):
                web_artifact.verify(artifact, dict(lock, proWeb={}))

    def test_ci_pro_lock_records_both_private_revisions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            (source / "index.html").write_text("pro fixture")
            (root / "upstream.lock.json").write_text(json.dumps(
                {"protocolVersion": 1, "specificationVersion": 4}))
            build_lock = root / "ci-lock.json"
            artifact = root / "sealed-pro"
            with patch.object(web_artifact, "ROOT", root):
                with self.assertRaisesRegex(ValueError, "requires a Pro build"):
                    web_artifact.seal(source, artifact, "wasm", lock_path=build_lock,
                                      client_commit="a" * 40, host_commit="b" * 40,
                                      host_pro_commit="d" * 40)
                web_artifact.seal(source, artifact, "wasm", "pro", lock_path=build_lock,
                                  client_commit="a" * 40, host_commit="b" * 40,
                                  pro_commit="c" * 40, host_pro_commit="d" * 40)
            lock = json.loads(build_lock.read_text())
            self.assertEqual(lock["hostCommit"], "b" * 40)
            self.assertEqual(lock["headlessProCommit"], "d" * 40)
            self.assertEqual(web_artifact.verify(artifact, lock)["proCommit"], "c" * 40)

    def test_missing_extra_and_tampered_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "index.html").write_text("fixed")
            files = web_artifact.inventory(root)
            tree = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            lock = {"upstreamCommit": "pin", "web": {"js": {"treeSha256": tree}}}
            manifest = {"upstreamCommit": "pin", "protocolVersion": 1, "kind": "js", "files": files}
            (root / web_artifact.MANIFEST).write_text(json.dumps(manifest))
            web_artifact.verify(root, lock)
            (root / "extra").write_text("unexpected")
            with self.assertRaises(ValueError):
                web_artifact.verify(root, lock)
            (root / "extra").unlink()
            (root / "index.html").write_text("changed")
            with self.assertRaises(ValueError):
                web_artifact.verify(root, lock)
            (root / "index.html").unlink()
            with self.assertRaises(ValueError):
                web_artifact.verify(root, lock)

    def test_license_bundle_rejects_stale_lock_extra_and_modified_text(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lock = root / "Cargo.lock"
            lock.write_text("fixed dependencies")
            bundle = root / "licenses"
            bundle.mkdir()
            (bundle / "index.json").write_text("[]")
            (bundle / "LICENSE").write_text("pinned license")
            manifest = {"version": 1, "target": "x86_64-unknown-linux-gnu",
                        "cargoLockSha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
                        "files": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in bundle.iterdir()}}
            (bundle / "bundle.json").write_text(json.dumps(manifest))
            portable.verify_licenses(bundle, "x86_64-unknown-linux-gnu", lock)
            lock.write_text("changed dependencies")
            with self.assertRaises(ValueError):
                portable.verify_licenses(bundle, "x86_64-unknown-linux-gnu", lock)
            lock.write_text("fixed dependencies")
            (bundle / "extra").write_text("untracked")
            with self.assertRaises(ValueError):
                portable.verify_licenses(bundle, "x86_64-unknown-linux-gnu", lock)
            (bundle / "extra").unlink()
            (bundle / "LICENSE").write_text("changed license")
            with self.assertRaises(ValueError):
                portable.verify_licenses(bundle, "x86_64-unknown-linux-gnu", lock)

    def test_collector_manifest_keeps_target_string(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            (source / "LICENSE").write_text("test license")
            (root / "Cargo.lock").write_text("test lock")
            metadata = {"resolve": {"root": "app", "nodes": [
                {"id": "app", "deps": [{"pkg": "dep", "dep_kinds": [{"kind": None}]}]},
                {"id": "dep", "deps": []}]},
                "packages": [{"id": "dep", "name": "test", "version": "1", "license": "MIT",
                              "manifest_path": str(source / "Cargo.toml")}]}
            with patch.object(collect_licenses, "ROOT", root), patch.object(
                    collect_licenses.subprocess, "check_output", return_value=json.dumps(metadata).encode()):
                collect_licenses.main("x86_64-unknown-linux-gnu")
            bundle = root / ".cache/third-party-licenses/x86_64-unknown-linux-gnu"
            portable.verify_licenses(bundle, "x86_64-unknown-linux-gnu", root / "Cargo.lock")

    def test_workspace_license_override_rejects_revision_and_text_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            vcs = source / ".cargo_vcs_info.json"
            vcs.write_text(json.dumps({"git": {"sha1": "pinned"}}))
            (root / "Cargo.lock").write_text("test lock")
            override = root / "licenses/test-1"
            override.mkdir(parents=True)
            for name in ["LICENSE-MIT", "NOTICE"]:
                (override / name).write_text("fixture " + name)
            (override / "override.json").write_text(json.dumps({"license": "MIT", "revision": "pinned",
                "files": {name: hashlib.sha256((override / name).read_bytes()).hexdigest() for name in ["LICENSE-MIT", "NOTICE"]}}))
            metadata = {"resolve": {"root": "app", "nodes": [
                {"id": "app", "deps": [{"pkg": "dep", "dep_kinds": [{"kind": None}]}]},
                {"id": "dep", "deps": []}]},
                "packages": [{"id": "dep", "name": "test", "version": "1", "license": "MIT",
                              "manifest_path": str(source / "Cargo.toml")}]}
            with patch.object(collect_licenses, "ROOT", root), patch.object(
                    collect_licenses.subprocess, "check_output", return_value=json.dumps(metadata).encode()):
                collect_licenses.main("x86_64-unknown-linux-gnu")
                vcs.write_text(json.dumps({"git": {"sha1": "pinned", "dirty": True}}))
                with self.assertRaises(ValueError):
                    collect_licenses.main("x86_64-unknown-linux-gnu")
                vcs.write_text(json.dumps({"git": {"sha1": "pinned"}}))
                manifest = json.loads((override / "override.json").read_text())
                manifest["archiveSha256"] = "pinned-archive"
                (override / "override.json").write_text(json.dumps(manifest))
                (root / "Cargo.lock").write_text('[[package]]\nname="test"\nversion="1"\nchecksum="changed-archive"\n')
                with self.assertRaises(ValueError):
                    collect_licenses.main("x86_64-unknown-linux-gnu")
                (root / "Cargo.lock").write_text('[[package]]\nname="test"\nversion="1"\nchecksum="pinned-archive"\n')
                collect_licenses.main("x86_64-unknown-linux-gnu")
                vcs.write_text(json.dumps({"git": {"sha1": "changed"}}))
                with self.assertRaises(ValueError):
                    collect_licenses.main("x86_64-unknown-linux-gnu")
                vcs.write_text(json.dumps({"git": {"sha1": "pinned"}}))
                (override / "LICENSE-MIT").write_text("changed")
                with self.assertRaises(ValueError):
                    collect_licenses.main("x86_64-unknown-linux-gnu")

    def test_windows_package_preserves_files_with_pre_zip_epoch_timestamps(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = "x86_64-pc-windows-msvc"
            for name in ("LICENSE", "NOTICE", "readme.md", "Cargo.lock"):
                (root / name).write_text("fixture " + name)
            (root / "Cargo.toml").write_text('[package]\nversion="0.1.0"\n')
            web = root / "web"
            web.mkdir()
            (web / "index.html").write_text("fixed web")
            files = web_artifact.inventory(web)
            tree = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            (root / "upstream.lock.json").write_text(json.dumps(
                {"upstreamCommit": "pinned", "proCommit": "private",
                 "web": {kind: {"treeSha256": tree} for kind in ("js", "wasm")},
                 "proWeb": {"js": {"treeSha256": tree}}}))
            (web / web_artifact.MANIFEST).write_text(json.dumps(
                {"upstreamCommit": "pinned", "protocolVersion": 1, "kind": "js", "files": files}))
            bundle = root / ".cache/third-party-licenses" / target
            bundle.mkdir(parents=True)
            (bundle / "index.json").write_text("[]")
            (bundle / "bundle.json").write_text(json.dumps({"version": 1, "target": target,
                "cargoLockSha256": hashlib.sha256((root / "Cargo.lock").read_bytes()).hexdigest(),
                "files": {"index.json": hashlib.sha256(b"[]").hexdigest()}}))
            binary = root / "host.exe"
            header = bytearray(128)
            header[:2] = b"MZ"
            header[0x3c:0x40] = (64).to_bytes(4, "little")
            header[64:68] = b"PE\0\0"
            header[68:70] = (0x8664).to_bytes(2, "little")
            binary.write_bytes(header)
            os.utime(root / "LICENSE", (0, 0))
            with patch.object(portable, "ROOT", root):
                output = portable.package(target, binary, web, root / "dist")
                manifest = json.loads((web / web_artifact.MANIFEST).read_text())
                (web / web_artifact.MANIFEST).write_text(json.dumps({**manifest, "kind": "wasm"}))
                wasm_output = portable.package(target, binary, web, root / "dist")
                empty_output = portable.package(target, binary, None, root / "dist")
                pro_output = portable.package(target, binary, None, root / "dist", edition="pro")
                (web / web_artifact.MANIFEST).write_text(json.dumps(
                    {**manifest, "edition": "pro", "proCommit": "private"}))
                with self.assertRaisesRegex(ValueError, "require standard Web"):
                    portable.package(target, binary, web, root / "dist")
            prefix = "FolderSpanHeadless-0.1.0-windows-x64-preview/"
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(archive.read(prefix + "LICENSE"), b"fixture LICENSE")
                self.assertEqual(archive.read(prefix + "README.md"), b"fixture readme.md")
                self.assertEqual(archive.getinfo(prefix + "LICENSE").date_time[0], 1980)
                sums = archive.read(prefix + "SHA256SUMS").decode()
                self.assertIn(hashlib.sha256(b"fixture LICENSE").hexdigest() + "  LICENSE", sums)
            with zipfile.ZipFile(wasm_output) as archive:
                self.assertIn("FolderSpanHeadless-0.1.0-windows-x64-wasm-preview/web-ui/index.html",
                              archive.namelist())
            with zipfile.ZipFile(empty_output) as archive:
                self.assertIn("FolderSpanHeadless-0.1.0-windows-x64-none-preview/folderspan-headless.exe",
                              archive.namelist())
                self.assertFalse(any("/web-ui/" in path for path in archive.namelist()))
            with zipfile.ZipFile(pro_output) as archive:
                self.assertIn("FolderSpanHeadless-0.1.0-windows-x64-pro-none-preview/upstream.lock.json",
                              archive.namelist())

    def test_binary_target_must_match(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "binary"
            header = bytearray(64)
            header[:5] = b"\x7fELF\x02"
            header[18:20] = (62).to_bytes(2, "little")
            path.write_bytes(header)
            portable.validate_binary(path, "x86_64-unknown-linux-gnu")
            with self.assertRaises(ValueError):
                portable.validate_binary(path, "aarch64-unknown-linux-gnu")

if __name__ == "__main__":
    unittest.main()
