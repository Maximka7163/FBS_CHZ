from __future__ import annotations

from wbcz_web.config import WebConfig
from wbcz_web.db import build_session_factory
from wbcz_web.services.worker_runtime import ProductionWorkerRuntime


def main() -> int:
    config = WebConfig.from_env().validate_for_startup()
    if config.process_role != "worker":
        raise SystemExit("WBCZ_PROCESS_ROLE=worker is required")
    if config.environment == "production":
        config.validate_m15_production_runtime()
    runtime = ProductionWorkerRuntime.build(build_session_factory(config), config)
    runtime.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
