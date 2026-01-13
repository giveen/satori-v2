import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--update-snapshots",
        action="store_true",
        default=False,
        help="Update stored os_inference snapshots from current run",
    )


@pytest.fixture
def update_snapshots(request):
    return request.config.getoption("--update-snapshots")
