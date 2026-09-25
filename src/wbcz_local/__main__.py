from __future__ import annotations

import argparse
import ipaddress

import uvicorn

from .app import LOCAL_BIND_HOST, LOCAL_DEFAULT_PORT


def _loopback_host(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("local Sellari host must be an IP loopback address") from exc
    if not address.is_loopback:
        raise argparse.ArgumentTypeError("local Sellari refuses non-loopback bind addresses")
    return str(address)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Sellari local WB FBS application")
    parser.add_argument("--host", type=_loopback_host, default=LOCAL_BIND_HOST)
    parser.add_argument("--port", type=int, default=LOCAL_DEFAULT_PORT)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    uvicorn.run(
        "wbcz_local.runtime:app",
        host=args.host,
        port=args.port,
        workers=1,
        reload=False,
        access_log=False,
    )


if __name__ == "__main__":
    main()
