"""
Void Vault Python SDK — Zero-Dependency Client & Capability Broker Bridge.

Allows any Python application (such as Void Trader or third-party desktop/server
applications) to embed Void Vault for:
  1. Encrypted multi-secret storage (`set_secret`, `get_secret`, `list_keys`)
  2. "Sign in with Void Vault" delegated authorization (`issue_token`, `verify_token`)
  3. Scoped secret access without exposing the master password (`get_secret_with_token`)
  4. Zero-knowledge per-app 256-bit key derivation (`derive_app_key`)
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


class VoidVaultError(RuntimeError):
    """Raised when Void Vault rejects an unauthorized or invalid operation."""


@dataclass(frozen=True)
class TokenVerification:
    app_id: str
    scope: str
    expires_at: int


class VoidVaultClient:
    """
    Communicates with `void_vault --broker` over an isolated, unbuffered
    stdin/stdout pipe. All secret payloads are hex-encoded on the pipe so
    arbitrary binary or multi-line secrets are transported safely.
    """

    def __init__(
        self,
        executable_path: str | Path,
        data_dir: str | Path = ".",
        kdf_profile: str = "interactive",
    ) -> None:
        self._exe = str(Path(executable_path).resolve())
        self._data_dir = str(Path(data_dir).resolve())
        self._kdf = kdf_profile
        self._proc: Optional[subprocess.Popen[str]] = None

    def open(self) -> "VoidVaultClient":
        if self._proc is not None and self._proc.poll() is None:
            return self
        self._proc = subprocess.Popen(
            [
                self._exe,
                "--data-dir",
                self._data_dir,
                "--kdf",
                self._kdf,
                "--broker",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        return self

    def close(self) -> None:
        if self._proc is None:
            return
        try:
            if self._proc.poll() is None and self._proc.stdin is not None:
                self._proc.stdin.write("QUIT\n")
                self._proc.stdin.flush()
                self._proc.wait(timeout=5)
        except Exception:
            self._proc.kill()
        finally:
            self._proc = None

    def __enter__(self) -> "VoidVaultClient":
        return self.open()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _request(self, line: str) -> str:
        if self._proc is None or self._proc.poll() is not None:
            raise VoidVaultError("VoidVaultClient broker process is not running")
        assert self._proc.stdin is not None and self._proc.stdout is not None
        self._proc.stdin.write(line + "\n")
        self._proc.stdin.flush()
        resp = self._proc.stdout.readline().strip()
        if not resp:
            err = self._proc.stderr.read() if self._proc.stderr else ""
            raise VoidVaultError(f"Void Vault broker closed unexpectedly: {err.strip()}")
        if resp.startswith("ERR "):
            raise VoidVaultError(resp[4:])
        if resp == "OK":
            return ""
        if resp.startswith("OK "):
            return resp[3:]
        raise VoidVaultError(f"Unexpected broker response: {resp}")

    def setup_account(self, master_password: str) -> None:
        pw_hex = master_password.encode("utf-8").hex()
        self._request(f"SETUP {pw_hex}")

    def unlock(self, master_password: str) -> None:
        pw_hex = master_password.encode("utf-8").hex()
        self._request(f"UNLOCK {pw_hex}")

    def lock(self) -> None:
        self._request("LOCK")

    def set_secret(self, key: str, value: str) -> None:
        val_hex = value.encode("utf-8").hex()
        self._request(f"SET_SECRET {key} {val_hex}")

    def get_secret(self, key: str) -> str:
        val_hex = self._request(f"GET_SECRET {key}")
        return bytes.fromhex(val_hex).decode("utf-8")

    def delete_secret(self, key: str) -> None:
        self._request(f"DELETE_SECRET {key}")

    def list_keys(self) -> List[str]:
        raw = self._request("LIST_KEYS").strip()
        return [k for k in raw.split(",") if k] if raw else []

    def issue_token(self, app_id: str, scope: str = "read:*", ttl_seconds: int = 300) -> str:
        """
        Issues a 'Sign in with Void Vault' capability token (`VVTOK1...`) for `app_id`
        with `scope` (e.g. 'read:trader.*', 'write:trader.*', 'key:mt5_password', 'auth:only').
        """
        return self._request(f"ISSUE_TOKEN {app_id} {scope} {int(ttl_seconds)}")

    def verify_token(self, token: str, app_id: str) -> TokenVerification:
        out = self._request(f"VERIFY_TOKEN {token} {app_id}")
        scope, expires_str = out.split(" ", 1)
        return TokenVerification(app_id=app_id, scope=scope, expires_at=int(expires_str))

    def get_secret_with_token(self, token: str, app_id: str, key: str) -> str:
        val_hex = self._request(f"TOKEN_GET_SECRET {token} {app_id} {key}")
        return bytes.fromhex(val_hex).decode("utf-8")

    def set_secret_with_token(self, token: str, app_id: str, key: str, value: str) -> None:
        val_hex = value.encode("utf-8").hex()
        self._request(f"TOKEN_SET_SECRET {token} {app_id} {key} {val_hex}")

    def derive_app_key(self, token: str, app_id: str, subkey_id: int = 1) -> bytes:
        """
        Derives a deterministic, isolated 32-byte (256-bit) encryption key for `app_id`
        without ever exposing the user's master password.
        """
        key_hex = self._request(f"DERIVE_APP_KEY {token} {app_id} {int(subkey_id)}")
        return bytes.fromhex(key_hex)

    def revoke_all_tokens(self) -> None:
        self._request("REVOKE_TOKENS")
