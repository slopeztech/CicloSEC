"""Tests for standards-validated SBOM parsing and normalization."""

import json
from pathlib import Path

import pytest

from ciclosec.inventory.models import SBOMDocument
from ciclosec.inventory.sbom import (
    SBOMValidationError,
    parse_sbom,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "sbom"


@pytest.mark.parametrize(
    ("sbom_format", "fixture"),
    [
        (SBOMDocument.Format.CYCLONEDX, "cyclonedx-1.7.json"),
        (SBOMDocument.Format.SPDX, "spdx-2.3.json"),
    ],
)
def test_valid_documents_are_normalized_with_dependency_relationships(
    sbom_format: str,
    fixture: str,
) -> None:
    payload = (FIXTURES / fixture).read_text(encoding="utf-8")

    result = parse_sbom(sbom_format, payload)

    assert result.format == sbom_format
    assert len(result.components) == 2
    assert result.components[0].relationship == "direct"
    assert result.components[1].relationship == "transitive"
    assert result.dependencies == (
        (("pkg-flask", "pkg-werkzeug"),)
        if sbom_format == SBOMDocument.Format.CYCLONEDX
        else (("SPDXRef-Flask", "SPDXRef-Werkzeug"),)
    )


def test_cyclonedx_validation_rejects_malformed_schema_without_echoing_input() -> None:
    secret_marker = "sensitive-component-name"
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "components": [{"name": secret_marker}],
    }

    with pytest.raises(SBOMValidationError) as error:
        parse_sbom(SBOMDocument.Format.CYCLONEDX, payload)

    assert "schema" in str(error.value)
    assert secret_marker not in str(error.value)


def test_invalid_purl_is_rejected() -> None:
    payload = json.loads((FIXTURES / "cyclonedx-1.7.json").read_text(encoding="utf-8"))
    payload["components"][0]["purl"] = "not-a-package-url"

    with pytest.raises(SBOMValidationError, match="package URL"):
        parse_sbom(SBOMDocument.Format.CYCLONEDX, payload)


def test_duplicate_json_keys_are_rejected() -> None:
    payload = '{"bomFormat":"CycloneDX","bomFormat":"SPDX"}'

    with pytest.raises(SBOMValidationError, match="duplicate"):
        parse_sbom(SBOMDocument.Format.CYCLONEDX, payload)


def test_unsupported_format_is_rejected() -> None:
    with pytest.raises(SBOMValidationError, match="CycloneDX or SPDX"):
        parse_sbom("unknown", {})
