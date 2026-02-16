"""
Test fixtures — shared across all test files.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_evidence():
    """Load all sample evidence objects."""
    with open(FIXTURES_DIR / "sample_evidence.json") as f:
        return json.load(f)


@pytest.fixture
def benign_evidence(sample_evidence):
    return sample_evidence["benign"]


@pytest.fixture
def suspicious_evidence(sample_evidence):
    return sample_evidence["suspicious"]


@pytest.fixture
def incomplete_evidence(sample_evidence):
    return sample_evidence["incomplete"]
