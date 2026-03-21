from __future__ import annotations

import getpass
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


KNOWN_SECRETS = [
    "UUID",
    "WS_PATH",
    "PROXYIP",
    "SOCKS5",
    "HTTP_PROXY",
    "DNS_UPSTREAM",
    "KEY",
    "PASSWORD",
]

MASKED_KEYS = {"UUID", "KEY", "PASSWORD", "SOCKS5", "HTTP_PROXY"}


@dataclass
class SecretState:
    name: str
    remote_present: bool
    local_value: str | None

    def local_status(self) -> str:
        if self.local_value is None:
            return "missing"
        return self.masked_value()

    def masked_value(self) -> str:
        if self.local_value is None:
            return "missing"
        if self.name not in MASKED_KEYS:
            return self.local_value
        if len(self.local_value) <= 6:
            return "*" * len(self.local_value)
        return f"{self.local_value[:3]}...{self.local_value[-3:]}"


class DevVarsStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def read(self) -> dict[str, str]:
        if not self.path.exists():
            return {}

        values: dict[str, str] = {}
        for line in self.path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            values[key.strip()] = value.strip()
        return values

    def write(self, values: dict[str, str]) -> None:
        lines = [f"{key}={values[key]}" for key in sorted(values)]
        self.path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    def set(self, key: str, value: str) -> None:
        values = self.read()
        values[key] = value
        self.write(values)


class WranglerSecretsApp:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.dev_vars = DevVarsStore(root / ".dev.vars")

    def run(self) -> int:
        while True:
            self.print_status()
            choice = input(
                "\nChoose action: [1] set remote [2] set local [3] push local -> remote [4] refresh [0] quit\n> "
            ).strip()

            if choice == "0":
                return 0
            if choice == "1":
                self.set_remote_secret()
            elif choice == "2":
                self.set_local_secret()
            elif choice == "3":
                self.push_local_to_remote()
            elif choice == "4":
                continue
            else:
                print("Unknown choice.")

    def print_status(self) -> None:
        states = self.collect_states()
        print("\nCurrent secret state\n")
        print(f"{'Name':<15} {'Remote':<10} {'Local':<30}")
        print(f"{'-' * 15} {'-' * 10} {'-' * 30}")
        for state in states:
            remote = "present" if state.remote_present else "missing"
            print(f"{state.name:<15} {remote:<10} {state.local_status():<30}")

    def collect_states(self) -> list[SecretState]:
        remote = self.fetch_remote_secret_names()
        local = self.dev_vars.read()
        return [
            SecretState(name=name, remote_present=name in remote, local_value=local.get(name))
            for name in KNOWN_SECRETS
        ]

    def fetch_remote_secret_names(self) -> set[str]:
        commands = [
            ["wrangler", "secret", "list", "--format", "json"],
            ["wrangler", "secret", "list", "--json"],
            ["wrangler", "secret", "list"],
        ]

        for command in commands:
            result = subprocess.run(command, cwd=self.root, text=True, capture_output=True)
            if result.returncode != 0:
                continue
            names = self.parse_secret_names(result.stdout)
            if names:
                return names
        return set()

    def parse_secret_names(self, output: str) -> set[str]:
        text = output.strip()
        if not text:
            return set()

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return {
                line.strip()
                for line in text.splitlines()
                if line.strip() and line.strip().isupper() and " " not in line.strip()
            }

        if isinstance(data, list):
            names = set()
            for item in data:
                if isinstance(item, dict) and isinstance(item.get("name"), str):
                    names.add(item["name"])
                elif isinstance(item, str):
                    names.add(item)
            return names
        return set()

    def set_remote_secret(self) -> None:
        key = self.prompt_secret_name()
        if not key:
            return
        value = self.prompt_secret_value(key)
        if value is None:
            return

        result = subprocess.run(
            ["wrangler", "secret", "put", key],
            cwd=self.root,
            text=True,
            input=value + "\n",
        )
        if result.returncode == 0:
            print(f"Remote secret updated: {key}")

    def set_local_secret(self) -> None:
        key = self.prompt_secret_name()
        if not key:
            return
        value = self.prompt_secret_value(key)
        if value is None:
            return
        self.dev_vars.set(key, value)
        print(f"Local .dev.vars updated: {key}")

    def push_local_to_remote(self) -> None:
        local = self.dev_vars.read()
        if not local:
            print("No local values found in .dev.vars")
            return

        available = [name for name in KNOWN_SECRETS if name in local]
        for index, name in enumerate(available, start=1):
            print(f"[{index}] {name}")
        raw = input("Select entries to push (comma separated, empty cancels):\n> ").strip()
        if not raw:
            return

        try:
            indexes = {int(item.strip()) for item in raw.split(",") if item.strip()}
        except ValueError:
            print("Invalid selection.")
            return

        for index, name in enumerate(available, start=1):
            if index not in indexes:
                continue
            subprocess.run(
                ["wrangler", "secret", "put", name],
                cwd=self.root,
                text=True,
                input=local[name] + "\n",
                check=False,
            )
            print(f"Pushed remote secret: {name}")

    def prompt_secret_name(self) -> str | None:
        for index, name in enumerate(KNOWN_SECRETS, start=1):
            print(f"[{index}] {name}")
        print("[9] custom")
        raw = input("Choose secret key:\n> ").strip().lower()
        if not raw:
            return None
        if raw == "9" or raw == "custom":
            custom = input("Custom key:\n> ").strip()
            return custom or None
        try:
            index = int(raw)
        except ValueError:
            return None
        if 1 <= index <= len(KNOWN_SECRETS):
            return KNOWN_SECRETS[index - 1]
        return None

    def prompt_secret_value(self, key: str) -> str | None:
        prompt = f"Enter value for {key}:\n> "
        if key in MASKED_KEYS:
            value = getpass.getpass(prompt)
        else:
            value = input(prompt)
        value = value.strip()
        return value or None


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    return WranglerSecretsApp(root).run()


if __name__ == "__main__":
    raise SystemExit(main())
