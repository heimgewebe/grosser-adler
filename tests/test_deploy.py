from pathlib import Path


def test_mcp_service_allows_netlink_for_read_only_socket_observation() -> None:
    root = Path(__file__).parents[1]
    mcp = (root / "deploy" / "grosser-adler-mcp.service").read_text(encoding="utf-8")
    tunnel = (root / "deploy" / "tunnel-client-grosser-adler.service").read_text(encoding="utf-8")

    mcp_line = next(
        line for line in mcp.splitlines() if line.startswith("RestrictAddressFamilies=")
    )
    tunnel_line = next(
        line for line in tunnel.splitlines() if line.startswith("RestrictAddressFamilies=")
    )

    assert mcp_line == "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK"
    assert "AF_NETLINK" not in tunnel_line


def test_mcp_service_exposes_only_lane_store_read_and_worktree_sidecar_write_roots() -> None:
    root = Path(__file__).parents[1]
    mcp = (root / "deploy" / "grosser-adler-mcp.service").read_text(encoding="utf-8")
    assert "Environment=GROSSER_ADLER_WORK_LANES_ROOT=%h/.local/state/grabowski/work-lanes" in mcp
    assert "Environment=GROSSER_ADLER_WORKTREE_ROOT=%h/repos/.grabowski-worktrees" in mcp
    assert "ReadOnlyPaths=%h/repos %h/.local/state/grabowski/work-lanes" in mcp
    assert "ReadWritePaths=%h/.local/state/grosser-adler %h/repos/.grabowski-worktrees" in mcp
    assert "ReadWritePaths=%h/repos\n" not in mcp


def test_mcp_service_scopes_lane_read_and_sidecar_write_paths() -> None:
    root = Path(__file__).parents[1]
    mcp = (root / "deploy" / "grosser-adler-mcp.service").read_text(encoding="utf-8")
    assert "Environment=GROSSER_ADLER_WORK_LANES_ROOT=%h/.local/state/grabowski/work-lanes" in mcp
    assert "Environment=GROSSER_ADLER_WORKTREE_ROOT=%h/repos/.grabowski-worktrees" in mcp
    assert "ProtectHome=read-only" in mcp
    assert "ReadOnlyPaths=%h/repos %h/.local/state/grabowski/work-lanes" in mcp
    assert "ReadWritePaths=%h/.local/state/grosser-adler %h/repos/.grabowski-worktrees" in mcp
