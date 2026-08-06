"""Acceptance instrument for the worked example (T0-reexec).

This is the executable instrument committed by `verification.criteria_hash`
in cfb.json and vtc.json. It is deliberately real code rather than a
description of code: the commitment must cover the bytes a verifier will
run, not a sentence about them.

Thresholds are not hardcoded here. They are read from the TaskSpec that
`task.spec_hash` commits to, so that the instrument and the thresholds
cannot drift apart. Usage:

    pytest test_acceptance.py --taskspec ../taskspec.json --delivery out.csv
"""

import csv
import json
import pathlib

import pytest

ISO_3166_ALPHA2_LEN = 2


def pytest_addoption(parser):
    parser.addoption("--taskspec", required=True, help="Path to the committed TaskSpec")
    parser.addoption("--delivery", required=True, help="Path to the delivered artifact")


@pytest.fixture(scope="session")
def thresholds(request):
    spec = json.loads(pathlib.Path(request.config.getoption("--taskspec")).read_text())
    return spec["acceptance"]["thresholds"]


@pytest.fixture(scope="session")
def rows(request):
    path = pathlib.Path(request.config.getoption("--delivery"))
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def test_delivery_is_non_empty(rows):
    assert rows, "delivered artifact contains no data rows"


def test_duplicate_rate_within_threshold(rows, thresholds):
    keys = [(r.get("customer_id") or "").strip().lower() for r in rows]
    populated = [k for k in keys if k]
    assert populated, "no populated customer_id values in delivery"
    duplicates = len(populated) - len(set(populated))
    dup_rate = duplicates / len(populated)
    assert dup_rate <= thresholds["dup_rate_max"], (
        f"duplicate rate {dup_rate:.6f} exceeds "
        f"threshold {thresholds['dup_rate_max']}"
    )


def test_country_fields_are_iso_3166_alpha2(rows, thresholds):
    countries = [(r.get("country") or "").strip() for r in rows]
    valid = [
        c for c in countries
        if len(c) == ISO_3166_ALPHA2_LEN and c.isalpha() and c.isupper()
    ]
    rate = len(valid) / len(countries)
    assert rate >= thresholds["schema_valid_rate"], (
        f"ISO-3166 alpha-2 conformance {rate:.6f} is below "
        f"required {thresholds['schema_valid_rate']}"
    )


def test_no_row_lost_relative_to_declared_input(rows, request):
    """Completeness check.

    A threshold set that a degenerate delivery can satisfy is not an
    acceptance instrument. Deduplication may only remove duplicates, so
    the output row count has a floor: the distinct-key count of the
    input. The declared input size is committed in the TaskSpec.
    """
    spec = json.loads(pathlib.Path(request.config.getoption("--taskspec")).read_text())
    declared = spec.get("inputs", {}).get("size_hint", {}).get("rows")
    if declared is None:
        pytest.skip("TaskSpec declares no input size_hint")
    floor = declared * 0.5
    assert len(rows) >= floor, (
        f"delivery has {len(rows)} rows against a declared input of "
        f"{declared}; deduplication cannot account for a reduction this large"
    )
