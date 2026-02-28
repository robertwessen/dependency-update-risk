"""Root pytest configuration."""

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--integration",
        action="store_true",
        default=False,
        help=(
            "Run integration tests that require external access "
            "(Docker for scanner tests; live GitHub/OSV/NVD APIs for SBOM ecosystem tests)"
        ),
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list) -> None:
    if not config.getoption("--integration"):
        skip = pytest.mark.skip(
            reason="pass --integration to run tests requiring Docker or external API access"
        )
        for item in items:
            if item.get_closest_marker("integration"):
                item.add_marker(skip)
