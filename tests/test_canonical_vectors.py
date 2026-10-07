"""Golden vectors for the canonical JSON encoding (extension #16, decision D8).

Every digest this tool emits is a SHA-256 of canonical JSON, so the encoder is
itself a check that can fail: these vectors pin its exact bytes. They also pin
the places where it deliberately differs from RFC 8785 (JCS), so the encoding
can never drift towards, or be described as, JCS without a test failing.

Characters outside ASCII are built with ``chr()`` and expected output is
spelled as explicit UTF-8 bytes, so no vector depends on how an editor
displays or stores an invisible character.
"""

from __future__ import annotations

import enum
import re
import unittest
from decimal import Decimal

from _helpers import SRC_DIR

from science_gate import _canonical
from science_gate._canonical import (
    MAX_SAFE_INTEGER,
    CanonicalizationError,
    StrictJSONError,
    canonical_bytes,
    canonical_dumps,
    normalize,
    sha256_canonical,
    strict_loads,
)
from science_gate.models import Status

#: U+E000, the first private-use code point: one UTF-16 code unit, 0xE000.
PRIVATE_USE = chr(0xE000)
#: U+FFFF, the last BMP code point.
LAST_BMP = chr(0xFFFF)
#: U+10000, the first code point beyond the BMP: UTF-16 surrogate pair D800 DC00.
FIRST_NON_BMP = chr(0x10000)
#: U+1F600: UTF-16 surrogate pair D83D DE00, UTF-8 F0 9F 98 80.
NON_BMP = chr(0x1F600)
#: U+2028 LINE SEPARATOR: JSON does not escape it, and neither does this encoder.
LINE_SEPARATOR = chr(0x2028)
E_ACUTE = chr(0xE9)


class _Colour(enum.Enum):
    """A non-string Enum whose value collides with a plain key once normalized."""

    RED = "red"


#: A fixed document touching every rule: key order (including a non-BMP key),
#: escapes, non-ASCII text, a Decimal that keeps its printed zero, an Enum, a
#: set, literals, and both safe-integer bounds.
GOLDEN_DOCUMENT = {
    "z": [3, -1, 0, True, False, None],
    "a": {NON_BMP: "grin", PRIVATE_USE: "private", "b": "x"},
    "text": f'quote" backslash\\ newline\n tab\t ctl\x01 caf{E_ACUTE} {LINE_SEPARATOR}',
    "decimal": Decimal("12.40"),
    "status": Status.ABSTAIN,
    "set": frozenset({"beta", "alpha"}),
    "max": MAX_SAFE_INTEGER,
    "min": -MAX_SAFE_INTEGER,
}

#: The exact canonical bytes of GOLDEN_DOCUMENT, written out by hand in UTF-8.
GOLDEN_BYTES = (
    b'{"a":{"b":"x","\xee\x80\x80":"private","\xf0\x9f\x98\x80":"grin"},'
    b'"decimal":"12.40",'
    b'"max":9007199254740991,'
    b'"min":-9007199254740991,'
    b'"set":["alpha","beta"],'
    b'"status":"ABSTAIN",'
    b'"text":"quote\\" backslash\\\\ newline\\n tab\\t ctl\\u0001 caf\xc3\xa9 \xe2\x80\xa8",'
    b'"z":[3,-1,0,true,false,null]}'
)

#: SHA-256 of GOLDEN_BYTES. Pinned so that any change to the encoder changes a test.
GOLDEN_SHA256 = "b567968290dbaaec6254d6a86907e0f75b36c275a04e03bf7cfb3fe5d2821b79"


def utf16_order(keys: list[str]) -> list[str]:
    """The key order RFC 8785 prescribes: by UTF-16 code units."""
    return sorted(keys, key=lambda key: key.encode("utf-16-be"))


def object_text(keys: list[str]) -> str:
    """``{"k1":0,"k2":0,...}`` with the keys in exactly the given order."""
    return "{" + ",".join(f'"{key}":0' for key in keys) + "}"


class KeyOrderVectors(unittest.TestCase):
    def test_a_non_bmp_key_sorts_after_u_e000_by_code_point(self) -> None:
        self.assertEqual(
            canonical_bytes({NON_BMP: 1, PRIVATE_USE: 2}),
            b'{"\xee\x80\x80":2,"\xf0\x9f\x98\x80":1}',
        )

    def test_that_order_is_where_jcs_would_differ(self) -> None:
        # The divergence is real: in UTF-16 the surrogate 0xD83D precedes 0xE000.
        keys = [PRIVATE_USE, NON_BMP]
        self.assertEqual(utf16_order(keys), [NON_BMP, PRIVATE_USE])
        for insertion in (keys, list(reversed(keys))):
            with self.subTest(insertion=[hex(ord(key)) for key in insertion]):
                text = canonical_dumps({key: 0 for key in insertion})
                self.assertEqual(text, object_text(keys))
                self.assertNotEqual(text, object_text(utf16_order(keys)))

    def test_mixed_planes_sort_by_code_point(self) -> None:
        keys = [FIRST_NON_BMP, LAST_BMP, PRIVATE_USE, "a"]
        by_code_point = ["a", PRIVATE_USE, LAST_BMP, FIRST_NON_BMP]
        self.assertEqual(canonical_dumps({key: 0 for key in keys}), object_text(by_code_point))
        self.assertEqual(utf16_order(keys), ["a", FIRST_NON_BMP, PRIVATE_USE, LAST_BMP])

    def test_nested_objects_sort_independently_of_insertion_order(self) -> None:
        forward = {"outer": {"b": 1, "a": 2}, "inner": [{"y": 0, "x": 0}]}
        backward = {"inner": [{"x": 0, "y": 0}], "outer": {"a": 2, "b": 1}}
        self.assertEqual(canonical_bytes(forward), b'{"inner":[{"x":0,"y":0}],"outer":{"a":2,"b":1}}')
        self.assertEqual(canonical_bytes(forward), canonical_bytes(backward))


class DuplicateKeyVectors(unittest.TestCase):
    def assert_duplicate(self, text: str) -> None:
        for integers_only in (False, True):
            with self.subTest(text=text, integers_only=integers_only):
                with self.assertRaises(StrictJSONError) as caught:
                    strict_loads(text, integers_only=integers_only)
                self.assertEqual(caught.exception.kind, "DUPLICATE_KEY")

    def test_literal_duplicates_are_refused(self) -> None:
        self.assert_duplicate('{"a":1,"a":1}')
        self.assert_duplicate('{"a":1,"a":2}')

    def test_duplicates_spelled_with_escapes_are_refused(self) -> None:
        # A JSON escape and the raw character are one key: a file must not say two things.
        self.assert_duplicate('{"a":1,"\\u0061":2}')
        self.assert_duplicate('{"x":[{"\\ud83d\\ude00":1,"' + NON_BMP + '":2}]}')

    def test_keys_that_collide_after_normalization_are_refused(self) -> None:
        with self.assertRaises(CanonicalizationError):
            normalize({_Colour.RED: 1, "red": 2})


class IntegerBoundVectors(unittest.TestCase):
    def test_the_bound_is_two_to_the_53_minus_one(self) -> None:
        self.assertEqual(MAX_SAFE_INTEGER, 9007199254740991)

    def test_plus_and_minus_the_bound_are_accepted(self) -> None:
        for value, text in ((MAX_SAFE_INTEGER, "9007199254740991"), (-MAX_SAFE_INTEGER, "-9007199254740991")):
            with self.subTest(value=value):
                self.assertEqual(canonical_dumps({"n": value}), '{"n":%s}' % text)
                self.assertEqual(strict_loads(text, integers_only=True), value)
                self.assertEqual(strict_loads(text), value)

    def test_plus_and_minus_two_to_the_53_are_refused(self) -> None:
        for value in (2**53, -(2**53), 2**64):
            with self.subTest(value=value):
                with self.assertRaises(CanonicalizationError) as caught:
                    normalize({"outer": [value]})
                self.assertIn("$.outer[0]", str(caught.exception))
                with self.assertRaises(StrictJSONError) as parsed:
                    strict_loads(f'{{"n": {value}}}', integers_only=True)
                self.assertEqual(parsed.exception.kind, "INTEGER_OUT_OF_RANGE")

    def test_input_data_keeps_an_unsafe_integer_as_a_decimal_string(self) -> None:
        # Data are not refused, but the value can never reach hashed content as a JSON number.
        value = strict_loads('{"id": 9007199254740993}')
        self.assertEqual(value, {"id": Decimal("9007199254740993")})
        self.assertEqual(canonical_dumps(value), '{"id":"9007199254740993"}')

    def test_booleans_are_not_integers(self) -> None:
        self.assertEqual(canonical_dumps([True, False]), "[true,false]")


class NonIntegerVectors(unittest.TestCase):
    def test_floats_are_refused(self) -> None:
        for value in (0.5, 1.0, -0.0, float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value), self.assertRaises(CanonicalizationError):
                canonical_bytes({"v": value})

    def test_non_finite_values_are_refused(self) -> None:
        for value in (Decimal("NaN"), Decimal("sNaN"), Decimal("Infinity"), Decimal("-Infinity")):
            with self.subTest(value=value), self.assertRaises(CanonicalizationError):
                canonical_bytes([value])
        for text in ("NaN", "[Infinity]", '{"v":-Infinity}'):
            for integers_only in (False, True):
                with self.subTest(text=text, integers_only=integers_only):
                    with self.assertRaises(StrictJSONError) as caught:
                        strict_loads(text, integers_only=integers_only)
                    self.assertEqual(caught.exception.kind, "NON_FINITE_NUMBER")

    def test_canonical_documents_refuse_fractions_and_exponents(self) -> None:
        for text in ("1.0", "1e2", "-0.5", "1E-7"):
            with self.subTest(text=text):
                with self.assertRaises(StrictJSONError) as caught:
                    strict_loads(f"[{text}]", integers_only=True)
                self.assertEqual(caught.exception.kind, "NON_INTEGER_NUMBER")

    def test_data_fractions_become_decimals_never_floats(self) -> None:
        value = strict_loads("[0.1, 1e2]")
        self.assertEqual(value, [Decimal("0.1"), Decimal("1E+2")])
        self.assertFalse(any(isinstance(item, float) for item in value))
        self.assertEqual(canonical_dumps(value), '["0.1","1E+2"]')


class GoldenDocumentVectors(unittest.TestCase):
    def test_exact_output_bytes(self) -> None:
        self.assertEqual(canonical_bytes(GOLDEN_DOCUMENT), GOLDEN_BYTES)

    def test_pinned_digest(self) -> None:
        self.assertEqual(sha256_canonical(GOLDEN_DOCUMENT), GOLDEN_SHA256)

    def test_round_trip_is_stable(self) -> None:
        reparsed = strict_loads(GOLDEN_BYTES, integers_only=True)
        self.assertEqual(canonical_bytes(reparsed), GOLDEN_BYTES)

    def test_lone_surrogates_have_no_canonical_bytes(self) -> None:
        with self.assertRaises(CanonicalizationError):
            canonical_bytes({chr(0xD83D): 1})


class NotJcsTests(unittest.TestCase):
    """D8: the encoding is never described as RFC 8785."""

    def test_the_module_says_it_is_not_rfc_8785(self) -> None:
        self.assertIn("**not** RFC 8785", _canonical.__doc__ or "")

    def test_no_source_file_claims_rfc_8785(self) -> None:
        mentions = 0
        for path in sorted((SRC_DIR / "science_gate").rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            for match in re.finditer(r"RFC\s*8785", text):
                mentions += 1
                preceding = text[max(0, match.start() - 24) : match.start()].lower()
                with self.subTest(file=path.name, offset=match.start()):
                    self.assertRegex(preceding, r"\b(not|never)\b")
        self.assertGreaterEqual(mentions, 1, "the disclaimer itself must stay in the source")


if __name__ == "__main__":
    unittest.main()
