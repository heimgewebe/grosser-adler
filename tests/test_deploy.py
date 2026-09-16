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
