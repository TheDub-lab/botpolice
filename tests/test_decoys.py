import json
import tempfile
import unittest
from pathlib import Path

from botpolice.config import load_config_with_source
from botpolice.decoys import (
    DecoyIdentity,
    load_identity,
    resolve_identity,
    save_identity,
)


class DecoyIdentityTests(unittest.TestCase):
    def test_random_shape(self) -> None:
        identity = DecoyIdentity.random()
        self.assertTrue(identity.ssh_banner.startswith("SSH-2.0-"))
        self.assertIn("ro.product.name", identity.adb_identity)
        self.assertTrue(identity.http_server)

    def test_random_is_not_the_constant_default(self) -> None:
        banners = {DecoyIdentity.random().ssh_banner for _ in range(20)}
        servers = {DecoyIdentity.random().http_server for _ in range(20)}
        self.assertGreater(len(banners), 1)
        self.assertGreater(len(servers), 1)

    def test_save_load_round_trip(self) -> None:
        identity = DecoyIdentity.random()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "decoys.json"
            save_identity(path, identity)
            loaded = load_identity(path)
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(loaded.ssh_banner, identity.ssh_banner)
            self.assertEqual(loaded.http_server, identity.http_server)
            self.assertEqual(loaded.adb_identity, identity.adb_identity)

    def test_load_missing_returns_none(self) -> None:
        self.assertIsNone(load_identity(Path("definitely-not-here-xyz.json")))

    def test_load_invalid_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "decoys.json"
            path.write_text("[1, 2, 3]", encoding="utf-8")
            self.assertIsNone(load_identity(path))

    def test_default_identity(self) -> None:
        self.assertEqual(DecoyIdentity.default().adb_identity["ro.product.name"], "tvbox")


class ResolveIdentityTests(unittest.TestCase):
    def _config(self, root: Path, data: dict | None = None):
        config_path = root / "config.json"
        config_path.write_text(json.dumps(data or {}), encoding="utf-8")
        config, _ = load_config_with_source(config_path)
        return config

    def test_auto_generate_creates_and_persists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self._config(root)
            first = resolve_identity(config)
            self.assertTrue(config.resolve(config.decoys.file).exists())
            second = resolve_identity(config)
            self.assertEqual(first.ssh_banner, second.ssh_banner)
            self.assertEqual(first.adb_identity, second.adb_identity)

    def test_explicit_overrides_win(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = self._config(
                Path(tmp),
                {"decoys": {"ssh_banner": "SSH-2.0-Custom_1.0", "http_server": "Custom/9"}},
            )
            identity = resolve_identity(config)
            self.assertEqual(identity.ssh_banner, "SSH-2.0-Custom_1.0")
            self.assertEqual(identity.http_server, "Custom/9")

    def test_auto_generate_disabled_uses_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = self._config(Path(tmp), {"decoys": {"auto_generate": False}})
            identity = resolve_identity(config)
            self.assertEqual(identity.ssh_banner, DecoyIdentity.default().ssh_banner)
            self.assertFalse(config.resolve(config.decoys.file).exists())


if __name__ == "__main__":
    unittest.main()
