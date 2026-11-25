"""Authenticated asset configuration API tests."""

import json
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient

from ciclosec.assets.models import Asset, ContainerImage, Repository
from ciclosec.inventory.models import SBOMDocument
from ciclosec.inventory.sbom import ingest_sbom
from ciclosec.scans.models import ScanRun

SBOM_FIXTURE = Path(__file__).parents[1] / "fixtures" / "sbom" / "cyclonedx-1.7.json"


@pytest.fixture
def api_client() -> APIClient:
    return APIClient()


@pytest.fixture
def authenticated_client(api_client: APIClient) -> APIClient:
    user_model = get_user_model()
    user = user_model.objects.create_user(username="ciclosec-test")
    api_client.force_authenticate(user=user)
    return api_client


@pytest.mark.django_db
def test_asset_endpoints_require_authentication(api_client: APIClient) -> None:
    response = api_client.get("/api/assets/")

    assert response.status_code in {401, 403}


@pytest.mark.django_db
def test_openapi_contract_and_docs_are_available(
    api_client: APIClient,
) -> None:
    contract = api_client.get("/api/openapi.json")
    docs = api_client.get("/api/docs/")

    assert contract.status_code == 200
    document = contract.json()
    assert document["openapi"] == "3.0.3"
    assert "/api/findings/{id}/decision/" in document["paths"]
    assert docs.status_code == 200
    assert b"/api/openapi.json" in docs.content


@pytest.mark.django_db
def test_asset_api_limit_offset_pagination_is_bounded_and_filterable(
    authenticated_client: APIClient,
) -> None:
    for index in range(6):
        Asset.objects.create(
            name=f"asset-{index}",
            kind=Asset.Kind.REPOSITORY,
            enabled=index % 2 == 0,
        )

    response = authenticated_client.get(
        "/api/assets/?limit=2&offset=2&kind=repository&enabled=true&search=asset"
    )

    assert response.status_code == 200
    assert response.data["total"] == 3
    assert response.data["limit"] == 2
    assert response.data["offset"] == 2
    assert len(response.data["items"]) == 1
    assert response.data["items"][0]["name"] == "asset-4"

    invalid = authenticated_client.get("/api/assets/?limit=101&offset=-1")
    assert invalid.status_code == 400


@pytest.mark.django_db
def test_authenticated_client_can_create_and_retrieve_asset(
    authenticated_client: APIClient,
) -> None:
    response = authenticated_client.post(
        "/api/assets/",
        {
            "name": "backend",
            "kind": Asset.Kind.REPOSITORY,
            "environment": Asset.Environment.PRODUCTION,
            "exposure": Asset.Exposure.INTERNET_FACING,
        },
        format="json",
    )

    assert response.status_code == 201
    asset_id = response.data["id"]
    detail = authenticated_client.get(f"/api/assets/{asset_id}/")
    assert detail.status_code == 200
    assert detail.data["name"] == "backend"


@pytest.mark.django_db
def test_repository_api_rejects_an_environment_value_as_a_credential(
    authenticated_client: APIClient,
) -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)

    response = authenticated_client.post(
        "/api/repositories/",
        {
            "asset": asset.pk,
            "owner": "ciclogreen",
            "repository_name": "backend",
            "credential_env": "ghp-not-a-variable-name",
        },
        format="json",
    )

    assert response.status_code == 400
    assert Repository.objects.count() == 0


@pytest.mark.django_db
def test_repository_api_rejects_container_asset_mismatch(
    authenticated_client: APIClient,
) -> None:
    image = Asset.objects.create(name="api", kind=Asset.Kind.CONTAINER_IMAGE)

    response = authenticated_client.post(
        "/api/repositories/",
        {
            "asset": image.pk,
            "owner": "ciclogreen",
            "repository_name": "backend",
        },
        format="json",
    )

    assert response.status_code == 400
    assert Repository.objects.count() == 0


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("field", "value"),
    [("owner", "../invalid"), ("repository_name", "bad/name"), ("ref", "-invalid")],
)
def test_repository_api_rejects_unscannable_sources(
    authenticated_client: APIClient, field: str, value: str
) -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    data = {"asset": asset.pk, "owner": "example", "repository_name": "backend", "ref": "main"}
    data[field] = value

    response = authenticated_client.post("/api/repositories/", data, format="json")

    assert response.status_code == 400
    assert not Repository.objects.exists()


@pytest.mark.django_db
def test_repository_api_validates_partial_updates_against_existing_source(
    authenticated_client: APIClient,
) -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    source = Repository.objects.create(asset=asset, owner="example", repository_name="backend")

    valid = authenticated_client.patch(
        f"/api/repositories/{source.pk}/", {"ref": "release/1"}, format="json"
    )
    invalid = authenticated_client.patch(
        f"/api/repositories/{source.pk}/", {"owner": "../invalid"}, format="json"
    )

    assert valid.status_code == 200
    assert invalid.status_code == 400
    source.refresh_from_db()
    assert source.owner == "example"
    assert source.ref == "release/1"


@pytest.mark.django_db
def test_existing_asset_kind_cannot_be_changed_via_api(
    authenticated_client: APIClient,
) -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="backend")

    response = authenticated_client.patch(
        f"/api/assets/{asset.pk}/", {"kind": Asset.Kind.CONTAINER_IMAGE}, format="json"
    )

    assert response.status_code == 400
    asset.refresh_from_db()
    assert asset.kind == Asset.Kind.REPOSITORY
    assert Repository.objects.filter(asset=asset).exists()


@pytest.mark.django_db
def test_container_api_rejects_unscannable_image_reference(
    authenticated_client: APIClient,
) -> None:
    asset = Asset.objects.create(name="image", kind=Asset.Kind.CONTAINER_IMAGE)

    response = authenticated_client.post(
        "/api/container-images/",
        {"asset": asset.pk, "image_reference": "--invalid"},
        format="json",
    )

    assert response.status_code == 400
    assert not ContainerImage.objects.exists()


@pytest.mark.django_db
def test_container_api_rejects_invalid_edits_without_changing_the_source(
    authenticated_client: APIClient,
) -> None:
    asset = Asset.objects.create(name="image", kind=Asset.Kind.CONTAINER_IMAGE)
    source = ContainerImage.objects.create(asset=asset, image_reference="example:local")

    response = authenticated_client.patch(
        f"/api/container-images/{source.pk}/",
        {"image_reference": "invalid image"},
        format="json",
    )

    assert response.status_code == 400
    source.refresh_from_db()
    assert source.image_reference == "example:local"


@pytest.mark.django_db
def test_container_api_clears_old_digest_only_when_reference_changes(
    authenticated_client: APIClient,
) -> None:
    asset = Asset.objects.create(name="image", kind=Asset.Kind.CONTAINER_IMAGE)
    resolved_at = timezone.now()
    source = ContainerImage.objects.create(
        asset=asset,
        image_reference="example:local",
        resolved_digest=f"sha256:{'a' * 64}",
        digest_resolved_at=resolved_at,
    )

    unchanged = authenticated_client.patch(
        f"/api/container-images/{source.pk}/",
        {"image_reference": "example:local"},
        format="json",
    )
    source.refresh_from_db()
    assert unchanged.status_code == 200
    assert source.resolved_digest == f"sha256:{'a' * 64}"
    assert source.digest_resolved_at == resolved_at

    changed = authenticated_client.patch(
        f"/api/container-images/{source.pk}/",
        {"image_reference": "example:other"},
        format="json",
    )
    source.refresh_from_db()
    assert changed.status_code == 200
    assert source.image_reference == "example:other"
    assert source.resolved_digest == ""
    assert source.digest_resolved_at is None


@pytest.mark.django_db
def test_container_api_clears_digest_when_source_moves_to_another_asset(
    authenticated_client: APIClient,
) -> None:
    asset = Asset.objects.create(name="image", kind=Asset.Kind.CONTAINER_IMAGE)
    other = Asset.objects.create(name="other", kind=Asset.Kind.CONTAINER_IMAGE)
    source = ContainerImage.objects.create(
        asset=asset,
        image_reference="example:local",
        resolved_digest=f"sha256:{'a' * 64}",
        digest_resolved_at=timezone.now(),
    )

    response = authenticated_client.patch(
        f"/api/container-images/{source.pk}/", {"asset": other.pk}, format="json"
    )

    source.refresh_from_db()
    assert response.status_code == 200
    assert source.asset_id == other.pk
    assert source.resolved_digest == ""
    assert source.digest_resolved_at is None


@pytest.mark.django_db
def test_authenticated_client_can_configure_container_image(
    authenticated_client: APIClient,
) -> None:
    asset = Asset.objects.create(name="nginx-production", kind=Asset.Kind.CONTAINER_IMAGE)

    response = authenticated_client.post(
        "/api/container-images/",
        {
            "asset": asset.pk,
            "image_reference": "nginx:1.27",
            "resolved_digest": f"sha256:{'a' * 64}",
            "digest_resolved_at": "2026-11-21T09:00:00Z",
        },
        format="json",
    )

    assert response.status_code == 201
    image = ContainerImage.objects.get(asset=asset)
    assert image.image_reference == "nginx:1.27"
    assert image.resolved_digest == ""
    assert image.digest_resolved_at is None


@pytest.mark.django_db
def test_asset_sbom_endpoint_returns_bounded_normalized_components(
    authenticated_client: APIClient,
) -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(
        asset=asset,
        scanner_name="test-scanner",
        status=ScanRun.Status.SUCCEEDED,
    )
    sbom = json.loads(SBOM_FIXTURE.read_text(encoding="utf-8"))
    ingest_sbom(scan, SBOMDocument.Format.CYCLONEDX, sbom)

    response = authenticated_client.get(f"/api/assets/{asset.pk}/sbom/?limit=1")

    assert response.status_code == 200
    assert response.data["asset_id"] == asset.pk
    assert response.data["total"] == 2
    assert len(response.data["items"]) == 1
    assert "purl" not in response.data["items"][0]
    assert "path" not in response.data["items"][0]

    oversized_page = authenticated_client.get(f"/api/assets/{asset.pk}/sbom/?limit=101")

    assert oversized_page.status_code == 400


@pytest.mark.django_db
def test_asset_sbom_endpoint_rejects_a_scan_run_from_another_asset(
    authenticated_client: APIClient,
) -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    other_asset = Asset.objects.create(name="frontend", kind=Asset.Kind.REPOSITORY)
    other_scan = ScanRun.objects.create(asset=other_asset, scanner_name="test-scanner")

    response = authenticated_client.get(f"/api/assets/{asset.pk}/sbom/?scan_run_id={other_scan.pk}")

    assert response.status_code == 400
