import re
from dataclasses import dataclass

import yaml


@dataclass
class HostConfig:
    allow_response_cookies: list[str] | None = None
    # None means no restriction; a list (even empty) enables filtering


@dataclass
class Config:
    allowlist: set[str]
    credentials: list[dict]
    host_config: dict[str, HostConfig]
    management_port: int = 8082


def _expand_secrets(obj, secrets: dict):
    """Recursively expand ${KEY} references in string values using the secrets map."""
    if isinstance(obj, str):
        def replace(m):
            key = m.group(1)
            if key not in secrets:
                raise KeyError(f"Secret key not found in secrets_file: ${{{key}}}")
            return str(secrets[key])
        return re.sub(r'\$\{([^}]+)\}', replace, obj)
    if isinstance(obj, dict):
        return {k: _expand_secrets(v, secrets) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_secrets(item, secrets) for item in obj]
    return obj


class ConfigLoader:
    def __init__(self, path: str):
        self._path = path

    def load(self) -> Config:
        data = self._load_raw()
        return Config(
            allowlist=self._parse_allowlist(data),
            credentials=self._parse_credentials(data),
            host_config=self._parse_host_config(data),
            management_port=int(data.get("management_port", 8082)),
        )

    def _load_raw(self) -> dict:
        try:
            with open(self._path) as f:
                data = yaml.safe_load(f) or {}
        except FileNotFoundError:
            return {}

        secrets = {}
        secrets_path = data.get("secrets_file")
        if secrets_path:
            with open(secrets_path) as f:
                secrets = yaml.safe_load(f) or {}

        return _expand_secrets(data, secrets)

    def _parse_allowlist(self, data: dict) -> set[str]:
        result = []
        for item in data.get("allowed_hosts", []):
            if isinstance(item, str):
                result.append(item)
            else:
                result.append(item["host"])
        return set(result)

    def _parse_host_config(self, data: dict) -> dict[str, HostConfig]:
        result = {}
        for item in data.get("allowed_hosts", []):
            if not isinstance(item, str):
                host = item["host"]
                result[host] = HostConfig(
                    allow_response_cookies=item.get("allow_response_cookies")
                )
        return result

    def _parse_credentials(self, data: dict) -> list[dict]:
        creds = data.get("credentials", [])
        # YAML block literals (|) and folded scalars (>) add a trailing newline.
        # Strip all credential values so that LF/CR never reach HTTP/2 header fields,
        # where they are forbidden (RFC 9113 § 8.2.1) and cause PROTOCOL_ERROR.
        for cred in creds:
            for key in ("real_value", "fake_value"):
                if key in cred and isinstance(cred[key], str):
                    cred[key] = cred[key].strip()
        return creds
