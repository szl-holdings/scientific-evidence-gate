"""Canonical JSON, strict parsing and SHA-256 helpers (sections 0 and 11)."""

from __future__ import annotations

import hashlib
import io
import os
import subprocess
import sys
import unittest
from collections.abc import Iterator, Mapping
from decimal import Decimal, InvalidOperation, localcontext
from pathlib import Path, PurePosixPath

from _helpers import SRC_DIR, TempDirTestCase

from science_gate._canonical import (
    HASH_CHUNK_BYTES,
    CanonicalizationError,
    SizeLimitExceeded,
    StrictJSONError,
    canonical_bytes,
    canonical_dumps,
    normalize,
    pretty_json_bytes,
    sha256_bytes,
    sha256_canonical,
    sha256_file,
    sha256_stream,
    strict_loads,
)
from science_gate.models import Reason, Status


class _HasToDict:
    def to_dict(self) -> dict[str, object]:
        return {"b": 2, "a": [1, Status.FAIL]}


class _RepeatingMapping(Mapping[str, int]):
    """A mapping that yields one key twice: two facts that would merge silently."""

    def __getitem__(self, key: str) -> int:
        return 1

    def __iter__(self) -> Iterator[str]:
        return iter(("same", "same"))

    def __len__(self) -> int:
        return 2


class CanonicalFormTests(unittest.TestCase):
    def test_keys_sorted_compact_and_utf8(self) -> None:
        self.assertEqual(canonical_dumps({"b": 1, "a": {"d": [], "c": None}}), '{"a":{"c":null,"d":[]},"b":1}')
        self.assertEqual(canonical_bytes({"name": "été"}), '{"name":"été"}'.encode("utf-8"))

    def test_floats_are_refused_with_their_location(self) -> None:
        with self.assertRaises(CanonicalizationError) as caught:
            canonical_dumps({"outer": [{"x": 0.1}]})
        self.assertIn("$.outer[0].x", str(caught.exception))
        with self.assertRaises(CanonicalizationError):
            canonical_dumps(1.0)

    def test_non_finite_decimals_are_refused(self) -> None:
        for value in (Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity"), Decimal("sNaN")):
            with self.subTest(value=value), self.assertRaises(CanonicalizationError):
                canonical_dumps({"v": value})

    def test_decimals_are_strings_that_keep_printed_precision(self) -> None:
        self.assertEqual(normalize(Decimal("0.125")), "0.125")
        self.assertEqual(normalize(Decimal("1.50")), "1.50")
        self.assertEqual(canonical_dumps([Decimal("12.40")]), '["12.40"]')

    def test_enums_serialize_as_their_values_in_keys_and_values(self) -> None:
        self.assertEqual(canonical_dumps({Status.PASS: Reason.VERIFIED}), '{"PASS":"VERIFIED"}')

    def test_non_string_keys_and_colliding_keys_are_refused(self) -> None:
        with self.assertRaises(CanonicalizationError):
            canonical_dumps({1: "one"})
        with self.assertRaises(CanonicalizationError):
            canonical_dumps(_RepeatingMapping())

    def test_sets_are_sorted_regardless_of_insertion_order(self) -> None:
        forward = {"delta", "alpha", "charlie", "bravo"}
        backward = set(reversed(sorted(forward)))
        self.assertEqual(canonical_dumps(forward), '["alpha","bravo","charlie","delta"]')
        self.assertEqual(canonical_dumps(forward), canonical_dumps(backward))
        self.assertEqual(canonical_dumps(frozenset({3, 1, 2})), "[1,2,3]")

    def test_bytes_paths_and_unknown_objects_are_refused(self) -> None:
        for value in (b"raw", bytearray(b"raw"), PurePosixPath("a/b"), Path("a"), object()):
            with self.subTest(value=type(value).__name__), self.assertRaises(CanonicalizationError):
                canonical_dumps(value)

    def test_objects_with_to_dict_are_normalized(self) -> None:
        self.assertEqual(canonical_dumps(_HasToDict()), '{"a":[1,"FAIL"],"b":2}')

    def test_lone_surrogates_cannot_be_hashed(self) -> None:
        with self.assertRaises(CanonicalizationError):
            canonical_bytes({"text": "\ud800"})

    def test_pretty_rendering_is_deterministic_indented_and_float_free(self) -> None:
        rendered = pretty_json_bytes({"b": 1, "a": Decimal("2.5")})
        self.assertEqual(rendered, b'{\n  "a": "2.5",\n  "b": 1\n}\n')
        with self.assertRaises(CanonicalizationError):
            pretty_json_bytes({"x": 2.5})


class HashTests(TempDirTestCase):
    def test_known_vector(self) -> None:
        self.assertEqual(sha256_bytes(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_canonical_hash_is_the_hash_of_canonical_bytes(self) -> None:
        value = {"z": [1, 2], "a": "x"}
        self.assertEqual(sha256_canonical(value), sha256_bytes(canonical_bytes(value)))
        self.assertEqual(sha256_canonical({"a": "x", "z": [1, 2]}), sha256_canonical(value))

    def test_stream_hash_matches_hashlib_across_chunk_boundaries(self) -> None:
        data = bytes(range(256)) * (HASH_CHUNK_BYTES // 256 * 3 + 7)
        digest, size = sha256_stream(io.BytesIO(data))
        self.assertEqual((digest, size), (hashlib.sha256(data).hexdigest(), len(data)))

    def test_stream_hash_enforces_the_byte_budget(self) -> None:
        self.assertEqual(sha256_stream(io.BytesIO(b"12345"), max_bytes=5)[1], 5)
        with self.assertRaises(SizeLimitExceeded):
            sha256_stream(io.BytesIO(b"123456"), max_bytes=5)

    def test_file_hash(self) -> None:
        path = self.write("data.bin", b"synthetic\r\nbytes\n")
        self.assertEqual(sha256_file(path), (hashlib.sha256(b"synthetic\r\nbytes\n").hexdigest(), 17))


class StrictLoadsTests(unittest.TestCase):
    def assertKind(self, kind: str, text: str | bytes, **kwargs: bool) -> StrictJSONError:
        with self.assertRaises(StrictJSONError) as caught:
            strict_loads(text, **kwargs)
        self.assertEqual(caught.exception.kind, kind)
        return caught.exception

    def test_duplicate_keys_are_refused_at_any_depth(self) -> None:
        self.assertKind("DUPLICATE_KEY", '{"a": 1, "a": 2}')
        self.assertKind("DUPLICATE_KEY", '{"outer": [{"k": 1, "k": 1}]}')

    def test_nan_and_infinity_are_refused(self) -> None:
        for text in ("NaN", "[Infinity]", '{"x": -Infinity}'):
            with self.subTest(text=text):
                self.assertKind("NON_FINITE_NUMBER", text)

    def test_fractions_become_decimals_never_floats(self) -> None:
        value = strict_loads('{"v": 0.1, "w": 1e3, "n": 7}')
        self.assertEqual(value, {"v": Decimal("0.1"), "w": Decimal("1E+3"), "n": 7})
        self.assertIsInstance(value["v"], Decimal)

    def test_unrepresentable_decimals_are_named_errors_under_either_trap_setting(self) -> None:
        # A short valid JSON token can exceed Decimal's implementation range.
        # The context must not decide between a raw exception and admitted NaN.
        tokens = ("1e9999999999999999999", "-1e9999999999999999999",
                  "1e-9999999999999999999", "0e9999999999999999999")
        for trapped in (True, False):
            with localcontext() as context:
                context.traps[InvalidOperation] = trapped
                original_flags = dict(context.flags)
                for token in tokens:
                    for text in (token, "[" + token + "]", '{"value":' + token + '}'):
                        for document in (text, text.encode("utf-8")):
                            with self.subTest(trapped=trapped, document=document):
                                self.assertKind("MALFORMED_JSON", document)
                                self.assertEqual(context.traps[InvalidOperation], trapped)
                                self.assertEqual(dict(context.flags), original_flags)

    def test_representable_decimal_precision_and_large_exponents_are_unchanged(self) -> None:
        for trapped in (True, False):
            with localcontext() as context:
                context.traps[InvalidOperation] = trapped
                for token in ("1.50", "-0.00", "1e999999", "1e-999999"):
                    with self.subTest(trapped=trapped, token=token):
                        parsed = strict_loads(token)
                        self.assertIsInstance(parsed, Decimal)
                        self.assertTrue(parsed.is_finite())
                        self.assertEqual(parsed.as_tuple(), Decimal(token).as_tuple())
                        self.assertEqual(canonical_bytes(parsed), canonical_bytes(Decimal(token)))

    def test_canonical_mode_still_refuses_unrepresentable_exponent_tokens(self) -> None:
        for trapped in (True, False):
            with localcontext() as context:
                context.traps[InvalidOperation] = trapped
                self.assertKind("NON_INTEGER_NUMBER", "1e9999999999999999999", integers_only=True)

    def test_integers_only_mode_refuses_fractions_and_exponents(self) -> None:
        self.assertKind("NON_INTEGER_NUMBER", "[1.5]", integers_only=True)
        self.assertKind("NON_INTEGER_NUMBER", "[1e3]", integers_only=True)
        self.assertEqual(strict_loads("[1, -2]", integers_only=True), [1, -2])

    def test_malformed_input_is_a_named_error_with_location(self) -> None:
        error = self.assertKind("MALFORMED_JSON", '{"a": 1,\n "b": }')
        self.assertEqual(error.line, 2)
        self.assertKind("MALFORMED_JSON", b"\xff\xfe{}")
        self.assertKind("MALFORMED_JSON", "[" * 100_000 + "]" * 100_000)
        self.assertKind("MALFORMED_JSON", "1" * 10_000)

    def test_byte_order_mark_is_accepted(self) -> None:
        self.assertEqual(strict_loads(b'\xef\xbb\xbf{"a": 1}'), {"a": 1})
        self.assertEqual(strict_loads('\ufeff{"a": 1}'), {"a": 1})


class HashSeedDeterminismTests(unittest.TestCase):
    """Requirement 13 at the lowest layer: output must not depend on PYTHONHASHSEED."""

    SNIPPET = (
        "import sys\n"
        "from science_gate._canonical import canonical_bytes\n"
        "names = {'sample-%03d' % i for i in range(200)}\n"
        "value = {'names': names, 'nested': {n: len(n) for n in names}, 'frozen': frozenset(names)}\n"
        "sys.stdout.write(canonical_bytes(value).hex())\n"
    )

    def canonical_output(self, seed: str) -> str:
        environment = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=str(SRC_DIR), PYTHONDONTWRITEBYTECODE="1")
        completed = subprocess.run(
            [sys.executable, "-c", self.SNIPPET],
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
        return completed.stdout

    def test_canonical_bytes_identical_under_different_hash_seeds(self) -> None:
        self.assertEqual(self.canonical_output("0"), self.canonical_output("4242"))


if __name__ == "__main__":
    unittest.main()

