from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parents[1]
DIST = ROOT / "packages" / "mcp-authz-python" / "dist"


def main() -> None:
    metadata = (DIST.parent / "pyproject.toml").read_text()
    match = re.search(r'^version = "([^"]+)"$', metadata, re.MULTILINE)
    if match is None:
        raise SystemExit("pyproject.toml has no project version.")
    version = match.group(1)
    wheels = sorted(DIST.glob(f"mcp_authz-{version}-*.whl"))
    if len(wheels) != 1:
        raise SystemExit(f"Expected one mcp-authz wheel in {DIST}, found {len(wheels)}.")

    with tempfile.TemporaryDirectory(prefix="mcp-authz-package-") as directory:
        environment = Path(directory) / "venv"
        run("uv", "venv", "--python", sys.executable, str(environment))
        python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        run("uv", "pip", "install", "--python", str(python), str(wheels[0]))
        run(
            str(python),
            "-c",
            "from mcp_authz import AuthorizedMCPServer, JwtVerifier, define_policy; "
            "assert callable(define_policy) and AuthorizedMCPServer and JwtVerifier",
        )


def run(*command: str) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
