"""The single time source and its fixed-time override (section 0)."""

from __future__ import annotations

import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from science_gate._clock import FIXED_TIME_ENV, ClockError, format_utc, now, parse_utc


class ClockTests(unittest.TestCase):
    def test_fixed_time_is_honored(self) -> None:
        with mock.patch.dict(os.environ, {FIXED_TIME_ENV: "2026-01-02T03:04:05Z"}):
            self.assertEqual(now(), "2026-01-02T03:04:05Z")
            self.assertEqual(now(), now())

    def test_fixed_time_is_reformatted_canonically(self) -> None:
        with mock.patch.dict(os.environ, {FIXED_TIME_ENV: "2026-01-02T03:04:05.000000Z"}):
            self.assertEqual(now(), "2026-01-02T03:04:05Z")

    def test_malformed_fixed_time_is_an_error_not_a_silent_wall_clock(self) -> None:
        for bad in ("2026-01-02 03:04:05", "2026-01-02T03:04:05+00:00", "2026-13-02T03:04:05Z", "yesterday"):
            with self.subTest(bad=bad), mock.patch.dict(os.environ, {FIXED_TIME_ENV: bad}):
                with self.assertRaises(ClockError):
                    now()

    def assertWallClock(self, stamp: str) -> None:
        self.assertRegex(stamp, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertLess(abs(datetime.now(timezone.utc) - parse_utc(stamp)), timedelta(minutes=5))

    def test_unset_uses_the_wall_clock_in_whole_seconds(self) -> None:
        with mock.patch.dict(os.environ):
            os.environ.pop(FIXED_TIME_ENV, None)
            self.assertWallClock(now())

    def test_empty_fixed_time_is_treated_as_unset(self) -> None:
        with mock.patch.dict(os.environ, {FIXED_TIME_ENV: ""}):
            self.assertWallClock(now())

    def test_parse_refuses_offsets_and_format_refuses_naive_datetimes(self) -> None:
        with self.assertRaises(ClockError):
            parse_utc("2026-01-02T03:04:05+02:00")
        with self.assertRaises(ClockError):
            format_utc(datetime(2026, 1, 2, 3, 4, 5))

    def test_format_converts_to_utc_and_keeps_microseconds_only_when_present(self) -> None:
        offset = timezone(timedelta(hours=2))
        self.assertEqual(format_utc(datetime(2026, 1, 2, 5, 4, 5, tzinfo=offset)), "2026-01-02T03:04:05Z")
        self.assertEqual(
            format_utc(datetime(2026, 1, 2, 3, 4, 5, 250, tzinfo=timezone.utc)), "2026-01-02T03:04:05.000250Z"
        )


if __name__ == "__main__":
    unittest.main()
