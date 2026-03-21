from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CommandResult:
    code: int
    stdout: str
    stderr: str

    def ok(self) -> bool:
        return self.code == 0


class Deployer:
    def __init__(self, root: Path) -> None:
        self.root = root

    def run(self) -> int:
        print("Deployment helper\n")
        if not self.check_auth():
            return 1

        if not self.confirm("Run release build before deploy?", default=True):
            return self.deploy()

        if not self.run_command(["cargo", "build", "--release"], "Release build").ok():
            return 1

        if self.confirm("Run worker-build release package?", default=True):
            if not self.run_command(["worker-build", "--release"], "Package wasm worker").ok():
                return 1

        if self.confirm("Open secret helper first?", default=False):
            secret_result = subprocess.run([sys.executable, "scripts/secrets.py"], cwd=self.root)
            if secret_result.returncode != 0:
                return secret_result.returncode

        return self.deploy()

    def deploy(self) -> int:
        if not self.confirm("Deploy with wrangler now?", default=True):
            print("Canceled.")
            return 0
        return self.run_command(["wrangler", "deploy"], "Wrangler deploy").code

    def check_auth(self) -> bool:
        result = self.run_command(["wrangler", "whoami"], "Check Wrangler auth", quiet=True)
        if result.ok():
            print(result.stdout.strip())
            return True

        print("Wrangler authentication check failed.")
        if result.stderr.strip():
            print(result.stderr.strip())
        if result.stdout.strip():
            print(result.stdout.strip())
        return False

    def run_command(self, command: list[str], title: str, quiet: bool = False) -> CommandResult:
        print(f"\n==> {title}")
        print("$ " + " ".join(command))
        result = subprocess.run(command, cwd=self.root, text=True, capture_output=quiet)
        if quiet:
            return CommandResult(result.returncode, result.stdout, result.stderr)
        return CommandResult(result.returncode, "", "")

    def confirm(self, question: str, default: bool) -> bool:
        suffix = "[Y/n]" if default else "[y/N]"
        raw = input(f"{question} {suffix} ").strip().lower()
        if not raw:
            return default
        return raw in {"y", "yes"}


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    return Deployer(root).run()


if __name__ == "__main__":
    raise SystemExit(main())
