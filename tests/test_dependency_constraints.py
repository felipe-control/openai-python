from __future__ import annotations

from importlib.metadata import requires

import pytest
from packaging.requirements import Requirement


@pytest.mark.parametrize(
    ("name", "extra", "affected", "patched"),
    [
        ("aiohttp", "aiohttp", "3.14.2", "3.14.3"),
        ("urllib3", "bedrock", "2.6.3", "2.7.0"),
    ],
)
def test_optional_network_dependency_security_floors(name: str, extra: str, affected: str, patched: str) -> None:
    requirements = [Requirement(value) for value in requires("openai") or []]
    matches = [requirement for requirement in requirements if requirement.name == name]
    assert len(matches) == 1
    requirement = matches[0]
    assert requirement.marker is not None
    assert requirement.marker.evaluate({"extra": extra})
    assert not requirement.marker.evaluate({"extra": ""})
    assert affected not in requirement.specifier
    assert patched in requirement.specifier


@pytest.mark.parametrize(
    ("name", "affected", "patched"),
    [
        # PYSEC-2026-3845..3849: request smuggling, multipart header injection,
        # decompression amplification, quadratic SSE parsing, SOCKS5 wss:// cleartext.
        ("httpx2", "2.11.9", "2.12.0"),
        # CVE-2026-63374 (IDN TLS hostname) and CVE-2026-64847 (undrained worker stderr).
        ("anyio", "4.14.1", "4.14.2"),
    ],
)
def test_base_network_dependency_security_floors(name: str, affected: str, patched: str) -> None:
    requirements = [Requirement(value) for value in requires("openai") or []]
    matches = [requirement for requirement in requirements if requirement.name == name]
    assert len(matches) == 1
    requirement = matches[0]
    assert requirement.marker is None
    assert affected not in requirement.specifier
    assert patched in requirement.specifier
