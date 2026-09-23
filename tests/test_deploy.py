import re
from pathlib import Path


def _unit() -> str:
    root = Path(__file__).parents[1]
    return (root / "deploy" / "grosser-adler-mcp.service").read_text(encoding="utf-8")


def _tunnel_example() -> str:
    root = Path(__file__).parents[1]
    return (root / "deploy" / "grosser-adler.yaml").read_text(encoding="utf-8")


def test_mcp_service_allows_netlink_for_read_only_socket_observation() -> None:
    root = Path(__file__).parents[1]
    mcp = _unit()
    tunnel = (root / "deploy" / "tunnel-client-grosser-adler.service").read_text(encoding="utf-8")
    mcp_line = next(line for line in mcp.splitlines() if line.startswith("RestrictAddressFamilies="))
    tunnel_line = next(line for line in tunnel.splitlines() if line.startswith("RestrictAddressFamilies="))
    assert mcp_line == "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK"
    assert "AF_NETLINK" not in tunnel_line


def test_mcp_service_start_pulls_in_tunnel_without_ordering_cycle() -> None:
    root = Path(__file__).parents[1]
    mcp = _unit()
    tunnel = (root / "deploy" / "tunnel-client-grosser-adler.service").read_text(encoding="utf-8")
    assert "Wants=tunnel-client-grosser-adler.service" in mcp
    assert "After=tunnel-client-grosser-adler.service" not in mcp
    assert "After=network-online.target grosser-adler-mcp.service" in tunnel
    assert "PartOf=grosser-adler-mcp.service" in tunnel


def test_mcp_service_keeps_repositories_read_only_and_writes_only_adler_state() -> None:
    mcp = _unit()
    assert "Environment=GROSSER_ADLER_WORK_LANES_ROOT=%h/.local/state/grabowski/work-lanes" in mcp
    assert "Environment=GROSSER_ADLER_WORKTREE_ROOT=%h/repos/.grabowski-worktrees" in mcp
    assert "ProtectHome=read-only" in mcp
    assert "ReadOnlyPaths=%h/repos %h/.local/state/grabowski/work-lanes" in mcp
    assert "ReadWritePaths=%h/.local/state/grosser-adler" in mcp
    read_write_lines = [line for line in mcp.splitlines() if line.startswith("ReadWritePaths=")]
    assert read_write_lines == ["ReadWritePaths=%h/.local/state/grosser-adler"]
    assert all(".grabowski-worktrees" not in line for line in read_write_lines)


def test_public_tunnel_example_contains_only_documented_identifier_placeholders() -> None:
    example = _tunnel_example()
    assert "Public example only." in example
    assert 'tunnel_id: "tunnel_REPLACE_ME"' in example
    assert 'OpenAI-Organization: "org_REPLACE_ME"' in example
    assert 'api_key: "env:CONTROL_PLANE_API_KEY"' in example
    assert re.search(r'tunnel_[0-9a-f]{32}', example) is None
    assert re.search(r'org-[A-Za-z0-9]{20,}', example) is None
