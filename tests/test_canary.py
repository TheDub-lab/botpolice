import tempfile
import unittest
from pathlib import Path

from botpolice.canary import CanaryStore, new_token


class CanaryStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store_path = self.root / "canaries.json"
        self.out_dir = self.root / "canaries"

    def _store(self) -> CanaryStore:
        return CanaryStore(self.store_path)

    def test_generate_creates_fake_file_and_token(self) -> None:
        store = self._store()
        record = store.generate("prod-web", "env", "http://127.0.0.1:8080", self.out_dir)

        self.assertTrue(record.token.startswith("bp-prod-web-"))
        self.assertTrue(Path(record.file).exists())
        content = Path(record.file).read_text(encoding="utf-8")
        self.assertIn(record.token, content)
        self.assertIn("DECOY", content)
        self.assertIn("http://127.0.0.1:8080", content)
        self.assertIn("EXAMPLE", content)  # AWS example key marker (obviously fake)

    def test_match_returns_placement(self) -> None:
        store = self._store()
        record = store.generate("prod-web", "env", "http://127.0.0.1:8080", self.out_dir)

        match = store.match(f"GET /?key={record.token} HTTP/1.1")
        self.assertIsNotNone(match)
        self.assertEqual(match.placement, "prod-web")
        self.assertEqual(match.token, record.token)

    def test_match_unknown_token_is_none(self) -> None:
        store = self._store()
        store.generate("prod-web", "env", "http://127.0.0.1:8080", self.out_dir)
        self.assertIsNone(store.match("no token here"))

    def test_persistence_across_instances(self) -> None:
        store = self._store()
        record = store.generate("db-box", "json", "http://127.0.0.1:8080", self.out_dir)

        reopened = CanaryStore(self.store_path)
        match = reopened.match(record.token)
        self.assertIsNotNone(match)
        self.assertEqual(match.placement, "db-box")

    def test_all_types_generate_and_match(self) -> None:
        store = self._store()
        for kind in ("env", "aws", "ssh", "json", "tripwire", "markdown", "agents", "claude"):
            record = store.generate(f"place-{kind}", kind, "http://10.0.0.5:8080", self.out_dir)
            self.assertTrue(Path(record.file).exists(), kind)
            content = Path(record.file).read_text(encoding="utf-8")
            self.assertIn(record.token, content, kind)
            self.assertIsNotNone(store.match(content), kind)

    def test_agent_instruction_tripwires(self) -> None:
        store = self._store()
        for kind in ("markdown", "agents", "claude"):
            record = store.generate(f"instr-{kind}", kind, "http://127.0.0.1:8080", self.out_dir)
            self.assertTrue(record.file.endswith(".md"), kind)
            content = Path(record.file).read_text(encoding="utf-8")
            self.assertIn(record.token, content, kind)
            self.assertIn(f"/t/{record.token}", content, kind)
            self.assertIn("AI", content, kind)  # addresses automated agents/assistants
            self.assertIn("<!--", content, kind)  # hidden tripwire comment
            self.assertIsNotNone(store.match(content), kind)

    def test_tripwire_contains_hidden_agent_instruction(self) -> None:
        store = self._store()
        record = store.generate("runbook", "tripwire", "http://127.0.0.1:8080", self.out_dir)
        content = Path(record.file).read_text(encoding="utf-8")
        self.assertIn("AI assistant", content)
        self.assertIn(f"/t/{record.token}", content)
        self.assertIn("<!--", content)

    def test_tokens_are_unique_per_placement(self) -> None:
        store = self._store()
        a = store.generate("same-name", "env", "http://x", self.out_dir)
        b = store.generate("same-name", "env", "http://x", self.out_dir)
        self.assertNotEqual(a.token, b.token)
        self.assertEqual(len(store), 2)

    def test_unknown_type_rejected(self) -> None:
        store = self._store()
        with self.assertRaises(ValueError):
            store.generate("x", "nope", "http://x", self.out_dir)

    def test_new_token_shape(self) -> None:
        token = new_token("Hello World!")
        self.assertTrue(token.startswith("bp-hello-world-"))
        self.assertEqual(len(token.split("-")[-1]), 32)


if __name__ == "__main__":
    unittest.main()
