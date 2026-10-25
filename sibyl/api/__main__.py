"""`uv run python -m sibyl.api`"""

import uvicorn

from sibyl.api.app import app


def main() -> None:
    uvicorn.run(app, host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
