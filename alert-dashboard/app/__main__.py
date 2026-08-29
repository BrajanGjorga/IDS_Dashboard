from __future__ import annotations

import uvicorn

from app.config import Settings


def main() -> None:
    settings = Settings.from_env()
    uvicorn.run("app.main:app", host=settings.app_host, port=settings.app_port)


if __name__ == "__main__":
    main()

