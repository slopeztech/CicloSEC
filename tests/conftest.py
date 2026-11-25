"""Shared pytest configuration."""

import pytest


@pytest.fixture
def configuration_state(db):
    """Recreate migration-provided singleton after transactional test database flushes."""
    from ciclosec.common.models import ConfigurationState

    ConfigurationState.objects.get_or_create(pk=1)
