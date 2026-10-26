"""
Void Vault v2.0 Python SDK — Zero-Dependency Client, Native C-ABI Bridge &
High-Level Developer Abstraction Layer (`VaultApp`).

Provides three levels of integration for any Python application (Fintech,
Desktop, Microservice, or CLI):

  1. High-Level Developer Abstraction (`VaultApp` & `ScopedSession`):
     3-line context-managed integration with automatic binary/DLL discovery,
     per-user directory isolation, automatic first-time setup, dictionary-style
     secret access (`secrets["card.pan"]`), prefix namespacing, and guaranteed
     vault lock + memory wipe on scope exit.

  2. Native In-Memory C-ABI Bridge (`VoidVaultNativeClient`):
     Zero-subprocess `ctypes` binding to `void_vault.dll` / `libvoid_vault.so`.

  3. Subprocess IPC Broker Bridge (`VoidVaultClient`):
     Communicates with `void_vault --broker` over an isolated stdin/stdout pipe.
"""

from __future__ import annotations

import ctypes
import functools
import os
import shutil
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, TypeVar, Any


class VoidVaultError(RuntimeError):
    """Raised when Void Vault rejects an unauthorized or invalid operation."""


@dataclass(frozen=True)
class TokenVerification:
    app_id: str
    scope: str
    expires_at: int


def _discover_binary_or_dll(
    explicit_path: Optional[str | Path] = None,
    prefer_dll: bool = True,
) -> tuple[str, Path]:
    """
    Auto-discovers either the shared library (`void_vault.dll` / `libvoid_vault.so`)
    or the executable (`void_vault.exe` / `void_vault`).
    Returns `("dll" | "exe", resolved_path)`.
    """
    if explicit_path is not None:
        p = Path(explicit_path).resolve()
        if not p.exists():
            raise VoidVaultError(f"Specified Void Vault binary/library does not exist: {p}")
        is_dll = p.suffix.lower() in (".dll", ".so", ".dylib")
        return ("dll" if is_dll else "exe", p)

    env_dll = os.environ.get("VOID_VAULT_DLL")
    if env_dll and Path(env_dll).exists():
        return ("dll", Path(env_dll).resolve())

    env_bin = os.environ.get("VOID_VAULT_BIN")
    if env_bin and Path(env_bin).exists():
        p = Path(env_bin).resolve()
        return ("dll" if p.suffix.lower() in (".dll", ".so", ".dylib") else "exe", p)

    cwd = Path.cwd()
    sdk_dir = Path(__file__).resolve().parent
    search_dirs = [
        cwd,
        cwd / "bin",
        cwd / "build",
        sdk_dir,
        sdk_dir.parent,
        sdk_dir.parent / "bin",
        sdk_dir.parent.parent / "build",
    ]

    dll_names = ["void_vault.dll", "libvoid_vault.dll", "libvoid_vault.so", "void_vault.so", "libvoid_vault.dylib"]
    exe_names = ["void_vault.exe", "void_vault"]

    if prefer_dll:
        for d in search_dirs:
            for name in dll_names:
                candidate = d / name
                if candidate.is_file():
                    return ("dll", candidate.resolve())

    for d in search_dirs:
        for name in exe_names:
            candidate = d / name
            if candidate.is_file():
                return ("exe", candidate.resolve())

    if not prefer_dll:
        for d in search_dirs:
            for name in dll_names:
                candidate = d / name
                if candidate.is_file():
                    return ("dll", candidate.resolve())

    which_exe = shutil.which("void_vault") or shutil.which("void_vault.exe")
    if which_exe:
        return ("exe", Path(which_exe).resolve())

    raise VoidVaultError(
        "Could not auto-discover 'void_vault.dll' or 'void_vault.exe'. "
        "Place it in your project directory, set VOID_VAULT_DLL / VOID_VAULT_BIN, "
        "or pass binary_path=... to VaultApp."
    )


class VoidVaultNativeClient:
    """
    In-process, zero-subprocess client bound directly to `void_vault.dll` / `libvoid_vault.so`
    via Python `ctypes` (C ABI v2).
    """

    def __init__(
        self,
        dll_path: str | Path,
        data_dir: str | Path = ".",
        kdf_profile: str = "interactive",
        idle_timeout_seconds: int = 0,
        auto_unseal: bool = False,
    ) -> None:
        self._dll_path = str(Path(dll_path).resolve())
        self._data_dir = Path(data_dir).resolve()
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._auth_path = str(self._data_dir / "vault_auth.dat")
        self._data_path = str(self._data_dir / "vault_data.dat")
        self._audit_path = str(self._data_dir / "vault_audit.log")
        self._kdf = kdf_profile
        self._idle_timeout = idle_timeout_seconds
        self._auto_unseal = auto_unseal
        self._lib = ctypes.CDLL(self._dll_path)
        self._bind_signatures()
        self._handle: Optional[ctypes.c_void_p] = None

    def _bind_signatures(self) -> None:
        L = self._lib
        L.vv_open_with_audit.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        L.vv_open_with_audit.restype = ctypes.c_void_p

        L.vv_close.argtypes = [ctypes.c_void_p]
        L.vv_close.restype = None

        L.vv_is_initialized.argtypes = [ctypes.c_void_p]
        L.vv_is_initialized.restype = ctypes.c_int

        L.vv_is_unlocked.argtypes = [ctypes.c_void_p]
        L.vv_is_unlocked.restype = ctypes.c_int

        L.vv_setup_password.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        L.vv_setup_password.restype = ctypes.c_int

        L.vv_unlock.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        L.vv_unlock.restype = ctypes.c_int

        L.vv_lock.argtypes = [ctypes.c_void_p]
        L.vv_lock.restype = None

        L.vv_enable_auto_unseal.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        L.vv_enable_auto_unseal.restype = ctypes.c_int

        L.vv_disable_auto_unseal.argtypes = [ctypes.c_void_p]
        L.vv_disable_auto_unseal.restype = ctypes.c_int

        L.vv_auto_unseal.argtypes = [ctypes.c_void_p]
        L.vv_auto_unseal.restype = ctypes.c_int

        L.vv_set_secret.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        L.vv_set_secret.restype = ctypes.c_int

        L.vv_get_secret.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        L.vv_get_secret.restype = ctypes.c_int

        L.vv_delete_secret.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        L.vv_delete_secret.restype = ctypes.c_int

        L.vv_set_ephemeral_secret.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_uint64,
        ]
        L.vv_set_ephemeral_secret.restype = ctypes.c_int

        L.vv_get_ephemeral_secret.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        L.vv_get_ephemeral_secret.restype = ctypes.c_int

        L.vv_delete_ephemeral_secret.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        L.vv_delete_ephemeral_secret.restype = ctypes.c_int

        L.vv_list_keys.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        L.vv_list_keys.restype = ctypes.c_int

        L.vv_issue_token.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_uint64,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        L.vv_issue_token.restype = ctypes.c_int

        L.vv_verify_token.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        L.vv_verify_token.restype = ctypes.c_int

        L.vv_get_secret_with_token.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        L.vv_get_secret_with_token.restype = ctypes.c_int

        L.vv_set_secret_with_token.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        L.vv_set_secret_with_token.restype = ctypes.c_int

        L.vv_derive_app_key.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_uint64,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        L.vv_derive_app_key.restype = ctypes.c_int

        L.vv_revoke_all_tokens.argtypes = [ctypes.c_void_p]
        L.vv_revoke_all_tokens.restype = ctypes.c_int

        L.vv_revoke_app_tokens.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        L.vv_revoke_app_tokens.restype = ctypes.c_int

        L.vv_generate_recovery_key.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        L.vv_generate_recovery_key.restype = ctypes.c_int

        L.vv_recover_with_emergency_key.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        L.vv_recover_with_emergency_key.restype = ctypes.c_int

        L.vv_verify_audit_log.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.POINTER(ctypes.c_size_t),
        ]
        L.vv_verify_audit_log.restype = ctypes.c_int

    def _require_handle(self) -> ctypes.c_void_p:
        if not self._handle:
            raise VoidVaultError("VoidVaultNativeClient is not open")
        return self._handle

    def open(self) -> "VoidVaultNativeClient":
        if self._handle is not None:
            return self
        h = self._lib.vv_open_with_audit(
            self._auth_path.encode("utf-8"),
            self._data_path.encode("utf-8"),
            self._audit_path.encode("utf-8"),
        )
        if not h:
            raise VoidVaultError(
                f"Failed to open Void Vault in '{self._data_dir}'"
            )
        self._handle = ctypes.c_void_p(h)
        if self._auto_unseal:
            try:
                self.auto_unseal()
            except VoidVaultError:
                self.close()
                raise
        return self

    def close(self) -> None:
        if self._handle is not None:
            self._lib.vv_close(self._handle)
            self._handle = None

    def __enter__(self) -> "VoidVaultNativeClient":
        return self.open()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def is_initialized(self) -> bool:
        return self._lib.vv_is_initialized(self._require_handle()) == 1

    def setup_account(self, master_password: str) -> None:
        rc = self._lib.vv_setup_password(self._require_handle(), master_password.encode("utf-8"))
        if rc != 1:
            raise VoidVaultError("setup_failed")

    def unlock(self, master_password: str) -> None:
        rc = self._lib.vv_unlock(self._require_handle(), master_password.encode("utf-8"))
        if rc != 1:
            raise VoidVaultError("auth_failed")

    def lock(self) -> None:
        if self._handle is not None:
            self._lib.vv_lock(self._handle)

    def enable_auto_unseal(self, current_password: str) -> None:
        rc = self._lib.vv_enable_auto_unseal(
            self._require_handle(), current_password.encode("utf-8")
        )
        if rc != 1:
            raise VoidVaultError("auto_unseal_enable_failed")

    def disable_auto_unseal(self) -> None:
        rc = self._lib.vv_disable_auto_unseal(self._require_handle())
        if rc != 1:
            raise VoidVaultError("auto_unseal_disable_failed")

    def auto_unseal(self) -> None:
        rc = self._lib.vv_auto_unseal(self._require_handle())
        if rc != 1:
            raise VoidVaultError("auto_unseal_failed")

    def set_secret(self, key: str, value: str) -> None:
        rc = self._lib.vv_set_secret(
            self._require_handle(), key.encode("utf-8"), value.encode("utf-8")
        )
        if rc != 1:
            raise VoidVaultError("set_secret_failed")

    def get_secret(self, key: str) -> str:
        buf = ctypes.create_string_buffer(65536)
        rc = self._lib.vv_get_secret(
            self._require_handle(), key.encode("utf-8"), buf, ctypes.sizeof(buf)
        )
        if rc != 1:
            raise VoidVaultError("get_secret_failed")
        return buf.value.decode("utf-8")

    def delete_secret(self, key: str) -> None:
        rc = self._lib.vv_delete_secret(self._require_handle(), key.encode("utf-8"))
        if rc != 1:
            raise VoidVaultError("delete_secret_failed")

    def set_ephemeral_secret(self, key: str, value: str, ttl_seconds: int) -> None:
        rc = self._lib.vv_set_ephemeral_secret(
            self._require_handle(),
            key.encode("utf-8"),
            value.encode("utf-8"),
            ctypes.c_uint64(int(ttl_seconds)),
        )
        if rc != 1:
            raise VoidVaultError("set_ephemeral_secret_failed")

    def get_ephemeral_secret(self, key: str) -> str:
        buf = ctypes.create_string_buffer(4097)
        rc = self._lib.vv_get_ephemeral_secret(
            self._require_handle(), key.encode("utf-8"), buf, ctypes.sizeof(buf)
        )
        if rc != 1:
            raise VoidVaultError("get_ephemeral_secret_failed")
        return buf.value.decode("utf-8")

    def delete_ephemeral_secret(self, key: str) -> None:
        rc = self._lib.vv_delete_ephemeral_secret(
            self._require_handle(), key.encode("utf-8")
        )
        if rc != 1:
            raise VoidVaultError("delete_ephemeral_secret_failed")

    def list_keys(self) -> List[str]:
        buf = ctypes.create_string_buffer(65536)
        rc = self._lib.vv_list_keys(self._require_handle(), buf, ctypes.sizeof(buf))
        if rc != 1:
            raise VoidVaultError("list_keys_failed")
        raw = buf.value.decode("utf-8").strip()
        return [k for k in raw.split(",") if k] if raw else []

    def issue_token(self, app_id: str, scope: str = "read:*", ttl_seconds: int = 300) -> str:
        buf = ctypes.create_string_buffer(1024)
        rc = self._lib.vv_issue_token(
            self._require_handle(),
            app_id.encode("utf-8"),
            scope.encode("utf-8"),
            ctypes.c_uint64(int(ttl_seconds)),
            buf,
            ctypes.sizeof(buf),
        )
        if rc != 1:
            raise VoidVaultError("issue_token_failed")
        return buf.value.decode("utf-8")

    def verify_token(self, token: str, app_id: str) -> TokenVerification:
        rc = self._lib.vv_verify_token(
            self._require_handle(),
            token.encode("utf-8"),
            app_id.encode("utf-8"),
        )
        if rc != 1:
            raise VoidVaultError("invalid_token")
        return TokenVerification(app_id=app_id, scope="*", expires_at=0)

    def get_secret_with_token(self, token: str, app_id: str, key: str) -> str:
        buf = ctypes.create_string_buffer(65536)
        rc = self._lib.vv_get_secret_with_token(
            self._require_handle(),
            token.encode("utf-8"),
            app_id.encode("utf-8"),
            key.encode("utf-8"),
            buf,
            ctypes.sizeof(buf),
        )
        if rc != 1:
            raise VoidVaultError("token_get_denied")
        return buf.value.decode("utf-8")

    def set_secret_with_token(self, token: str, app_id: str, key: str, value: str) -> None:
        rc = self._lib.vv_set_secret_with_token(
            self._require_handle(),
            token.encode("utf-8"),
            app_id.encode("utf-8"),
            key.encode("utf-8"),
            value.encode("utf-8"),
        )
        if rc != 1:
            raise VoidVaultError("token_set_denied")

    def derive_app_key(self, token: str, app_id: str, subkey_id: int = 1) -> bytes:
        buf = ctypes.create_string_buffer(128)
        rc = self._lib.vv_derive_app_key(
            self._require_handle(),
            token.encode("utf-8"),
            app_id.encode("utf-8"),
            ctypes.c_uint64(int(subkey_id)),
            buf,
            ctypes.sizeof(buf),
        )
        if rc != 1:
            raise VoidVaultError("derive_key_denied")
        return bytes.fromhex(buf.value.decode("utf-8"))

    def revoke_all_tokens(self) -> None:
        if self._lib.vv_revoke_all_tokens(self._require_handle()) != 1:
            raise VoidVaultError("revoke_failed")

    def revoke_app_tokens(self, app_id: str) -> None:
        if self._lib.vv_revoke_app_tokens(self._require_handle(), app_id.encode("utf-8")) != 1:
            raise VoidVaultError("revoke_app_failed")

    def generate_recovery_key(self) -> str:
        buf = ctypes.create_string_buffer(128)
        rc = self._lib.vv_generate_recovery_key(
            self._require_handle(), buf, ctypes.sizeof(buf)
        )
        if rc != 1:
            raise VoidVaultError("generate_recovery_failed")
        return buf.value.decode("utf-8")

    def recover_with_key(self, recovery_key: str, new_master_password: str) -> None:
        rc = self._lib.vv_recover_with_emergency_key(
            self._require_handle(),
            recovery_key.encode("utf-8"),
            new_master_password.encode("utf-8"),
        )
        if rc != 1:
            raise VoidVaultError("recovery_failed")

    def verify_audit(self) -> int:
        count = ctypes.c_size_t(0)
        failed_line = ctypes.c_size_t(0)
        rc = self._lib.vv_verify_audit_log(
            self._audit_path.encode("utf-8"),
            ctypes.byref(count),
            ctypes.byref(failed_line),
        )
        if rc != 1:
            raise VoidVaultError(f"audit_tampered at line {failed_line.value}")
        return int(count.value)


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
        idle_timeout_seconds: int = 0,
        auto_unseal: bool = False,
    ) -> None:
        self._exe = str(Path(executable_path).resolve())
        self._data_dir = str(Path(data_dir).resolve())
        self._kdf = kdf_profile
        self._idle_timeout = int(idle_timeout_seconds)
        self._auto_unseal = bool(auto_unseal)
        self._proc: Optional[subprocess.Popen[str]] = None

    def open(self) -> "VoidVaultClient":
        if self._proc is not None and self._proc.poll() is None:
            return self
        Path(self._data_dir).mkdir(parents=True, exist_ok=True)
        cmd = [
            self._exe,
            "--data-dir",
            self._data_dir,
            "--kdf",
            self._kdf,
            "--broker",
        ]
        if self._auto_unseal:
            cmd.append("--auto-unseal")
        if self._idle_timeout > 0:
            cmd.extend(["--idle-timeout", str(self._idle_timeout)])
        self._proc = subprocess.Popen(
            cmd,
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

    def enable_auto_unseal(self, current_password: str) -> None:
        password_hex = current_password.encode("utf-8").hex()
        self._request(f"ENABLE_AUTO_UNSEAL {password_hex}")

    def disable_auto_unseal(self) -> None:
        self._request("DISABLE_AUTO_UNSEAL")

    def set_secret(self, key: str, value: str) -> None:
        val_hex = value.encode("utf-8").hex()
        self._request(f"SET_SECRET {key} {val_hex}")

    def get_secret(self, key: str) -> str:
        val_hex = self._request(f"GET_SECRET {key}")
        return bytes.fromhex(val_hex).decode("utf-8")

    def delete_secret(self, key: str) -> None:
        self._request(f"DELETE_SECRET {key}")

    def set_ephemeral_secret(self, key: str, value: str, ttl_seconds: int) -> None:
        val_hex = value.encode("utf-8").hex()
        self._request(f"SET_EPHEMERAL_SECRET {key} {int(ttl_seconds)} {val_hex}")

    def get_ephemeral_secret(self, key: str) -> str:
        val_hex = self._request(f"GET_EPHEMERAL_SECRET {key}")
        return bytes.fromhex(val_hex).decode("utf-8")

    def delete_ephemeral_secret(self, key: str) -> None:
        self._request(f"DELETE_EPHEMERAL_SECRET {key}")

    def list_keys(self) -> List[str]:
        raw = self._request("LIST_KEYS").strip()
        return [k for k in raw.split(",") if k] if raw else []

    def issue_token(self, app_id: str, scope: str = "read:*", ttl_seconds: int = 300) -> str:
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
        key_hex = self._request(f"DERIVE_APP_KEY {token} {app_id} {int(subkey_id)}")
        return bytes.fromhex(key_hex)

    def transit_encrypt(
        self, token: str, app_id: str, key_id: str, plaintext: bytes
    ) -> bytes:
        payload_hex = bytes(plaintext).hex()
        ciphertext_hex = self._request(
            f"TRANSIT_ENCRYPT {token} {app_id} {key_id} {payload_hex}"
        )
        return bytes.fromhex(ciphertext_hex)

    def transit_decrypt(
        self, token: str, app_id: str, key_id: str, ciphertext: bytes
    ) -> bytes:
        ciphertext_hex = bytes(ciphertext).hex()
        plaintext_hex = self._request(
            f"TRANSIT_DECRYPT {token} {app_id} {key_id} {ciphertext_hex}"
        )
        return bytes.fromhex(plaintext_hex)

    def pki_create_authority(self, authority_id: str, common_name: str) -> str:
        common_name_hex = common_name.encode("utf-8").hex()
        certificate_hex = self._request(
            f"PKI_CREATE_CA {authority_id} {common_name_hex}"
        )
        return bytes.fromhex(certificate_hex).decode("ascii")

    def pki_issue_certificate(
        self, authority_id: str, common_name: str, validity_days: int = 90
    ) -> str:
        common_name_hex = common_name.encode("utf-8").hex()
        certificate_hex = self._request(
            f"PKI_ISSUE_CERTIFICATE {authority_id} "
            f"{int(validity_days)} {common_name_hex}"
        )
        return bytes.fromhex(certificate_hex).decode("ascii")

    def revoke_all_tokens(self) -> None:
        self._request("REVOKE_TOKENS")

    def revoke_app_tokens(self, app_id: str) -> None:
        self._request(f"REVOKE_APP_TOKENS {app_id}")

    def generate_recovery_key(self) -> str:
        return self._request("GENERATE_RECOVERY_KEY")

    def recover_with_key(self, recovery_key: str, new_master_password: str) -> None:
        rec_hex = recovery_key.encode("utf-8").hex()
        pw_hex = new_master_password.encode("utf-8").hex()
        self._request(f"RECOVER_WITH_KEY {rec_hex} {pw_hex}")

    def verify_audit(self) -> int:
        out = self._request("VERIFY_AUDIT")
        return int(out.strip())


# ============================================================================
# High-Level Developer Abstraction Layer (`VaultApp` & `ScopedSession`)
# ============================================================================


class NamespacedSecrets:
    """
    Dictionary-like view over a key prefix (e.g. `secrets.namespace("card.")`),
    allowing `card["pan"] = "..."` to transparently read/write `"card.pan"`.
    """

    def __init__(self, session: "ScopedSession", prefix: str) -> None:
        self._session = session
        self._prefix = prefix

    def __getitem__(self, subkey: str) -> str:
        return self._session[f"{self._prefix}{subkey}"]

    def __setitem__(self, subkey: str, value: str) -> None:
        self._session[f"{self._prefix}{subkey}"] = value

    def get(self, subkey: str, default: Optional[str] = None) -> Optional[str]:
        return self._session.get(f"{self._prefix}{subkey}", default)


class ScopedSession:
    """
    High-level, capability-scoped secret session yielded by `with app.session(...) as secrets:`.
    All reads and writes go through a short-lived `VVTOK1` capability token bound
    to `app_id` and `scope`, enforcing least privilege automatically.
    """

    def __init__(
        self,
        backend: VoidVaultNativeClient | VoidVaultClient,
        app_id: str,
        scope: str,
        token: str,
    ) -> None:
        self._backend = backend
        self.app_id = app_id
        self.scope = scope
        self.token = token

    def __getitem__(self, key: str) -> str:
        try:
            return self._backend.get_secret_with_token(self.token, self.app_id, key)
        except VoidVaultError as exc:
            raise KeyError(f"Secret '{key}' not found or denied by scope '{self.scope}': {exc}") from exc

    def __setitem__(self, key: str, value: str) -> None:
        self._backend.set_secret_with_token(self.token, self.app_id, key, str(value))

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        try:
            return self._backend.get_secret_with_token(self.token, self.app_id, key)
        except VoidVaultError:
            return default

    def delete(self, key: str) -> None:
        self._backend.delete_secret(key)

    def namespace(self, prefix: str) -> NamespacedSecrets:
        """Returns a prefix-scoped dictionary view (e.g. `secrets.namespace("card.")`)."""
        return NamespacedSecrets(self, prefix)

    def derive_key(self, subkey_id: int = 1) -> bytes:
        """
        Derives a deterministic, isolated 32-byte (256-bit) cryptographic key
        for this application without exposing the user's master password.
        """
        return self._backend.derive_app_key(self.token, self.app_id, subkey_id=subkey_id)

    def transit_encrypt(self, key_id: str, plaintext: bytes) -> bytes:
        """Encrypts data in the daemon; requires a daemon IPC backend and transit:encrypt scope."""
        if not isinstance(self._backend, VoidVaultClient):
            raise VoidVaultError(
                "Transit requires the daemon IPC backend; configure prefer_native_dll=False"
            )
        return self._backend.transit_encrypt(
            self.token, self.app_id, key_id, plaintext
        )

    def transit_decrypt(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypts data in the daemon; requires a daemon IPC backend and transit:decrypt scope."""
        if not isinstance(self._backend, VoidVaultClient):
            raise VoidVaultError(
                "Transit requires the daemon IPC backend; configure prefer_native_dll=False"
            )
        return self._backend.transit_decrypt(
            self.token, self.app_id, key_id, ciphertext
        )

    def issue_delegated_token(self, target_app_id: str, scope: str, ttl_seconds: int = 300) -> str:
        """Mints a secondary capability token for a downstream microservice/worker."""
        return self._backend.issue_token(target_app_id, scope=scope, ttl_seconds=ttl_seconds)

    def revoke_app_tokens(self, target_app_id: Optional[str] = None) -> None:
        """Immediately invalidates all tokens issued for `target_app_id` (default: this app)."""
        self._backend.revoke_app_tokens(target_app_id or self.app_id)

    def generate_recovery_key(self) -> str:
        """Generates a one-time Emergency Recovery Key (`VVREC-...`) for this vault."""
        return self._backend.generate_recovery_key()

    def verify_audit_log(self) -> int:
        """Verifies the BLAKE2b-256 tamper-evident audit chain and returns the entry count."""
        return self._backend.verify_audit()


def _scope_satisfies(granted: str, required: str) -> bool:
    if granted == "*":
        return True
    if granted == required:
        return True
    if granted == "read:*" and required.startswith("read:"):
        return True
    if granted.endswith("*") and required.startswith(granted[:-1]):
        return True
    return False


F = TypeVar("F", bound=Callable[..., Any])


class VaultApp:
    """
    Production Developer Abstraction for Void Vault v2.0.

    Example (3-line integration):
    ```python
    from void_vault import VaultApp

    vault = VaultApp(app_id="acme-banking", scope="*", vault_root="./user_vaults")

    with vault.session(user_id="customer_1042", passphrase=user_pin) as secrets:
        secrets["card.pan"] = "4532-xxxx-xxxx-8891"
        pan = secrets["card.pan"]
        app_key = secrets.derive_key(subkey_id=1)
    # Vault is automatically locked and wiped in RAM the instant the `with` block exits!
    ```
    """

    def __init__(
        self,
        app_id: str,
        scope: str = "*",
        vault_root: str | Path = ".",
        ttl_seconds: int = 300,
        kdf_profile: str = "interactive",
        idle_timeout_seconds: int = 0,
        binary_path: Optional[str | Path] = None,
        prefer_native_dll: bool = True,
        auto_unseal: bool = False,
    ) -> None:
        self.app_id = app_id
        self.scope = scope
        self.vault_root = Path(vault_root).resolve()
        self.ttl_seconds = ttl_seconds
        self.kdf_profile = kdf_profile
        self.idle_timeout_seconds = idle_timeout_seconds
        self._explicit_binary = binary_path
        self._prefer_dll = prefer_native_dll
        self.auto_unseal = auto_unseal

    def _resolve_user_dir(self, user_id: Optional[str]) -> Path:
        if not user_id:
            self.vault_root.mkdir(parents=True, exist_ok=True)
            return self.vault_root
        safe_id = "".join(c for c in user_id if c.isalnum() or c in ("-", "_", "."))
        if not safe_id:
            raise VoidVaultError(f"Invalid user_id: {user_id!r}")
        user_dir = self.vault_root / safe_id
        user_dir.mkdir(parents=True, exist_ok=True)
        return user_dir

    def _create_backend(self, data_dir: Path) -> VoidVaultNativeClient | VoidVaultClient:
        kind, resolved_path = _discover_binary_or_dll(
            self._explicit_binary, prefer_dll=self._prefer_dll
        )
        if kind == "dll":
            return VoidVaultNativeClient(
                dll_path=resolved_path,
                data_dir=data_dir,
                kdf_profile=self.kdf_profile,
                idle_timeout_seconds=self.idle_timeout_seconds,
                auto_unseal=self.auto_unseal,
            )
        return VoidVaultClient(
            executable_path=resolved_path,
            data_dir=data_dir,
            kdf_profile=self.kdf_profile,
            idle_timeout_seconds=self.idle_timeout_seconds,
            auto_unseal=self.auto_unseal,
        )

    @contextmanager
    def session(
        self,
        passphrase: str,
        user_id: Optional[str] = None,
        scope: Optional[str] = None,
        auto_setup: bool = True,
    ) -> Iterator[ScopedSession]:
        """
        Opens an isolated, capability-scoped session for `user_id` (or the root vault).
        - Automatically initializes the vault on first use when `auto_setup=True`.
        - Unlocks the vault and issues a scoped `VVTOK1` token for `self.app_id`.
        - Automatically locks and wipes the vault in RAM upon exiting the `with` block.
        """
        data_dir = self._resolve_user_dir(user_id)
        auth_file = data_dir / "vault_auth.dat"
        effective_scope = scope or self.scope

        with self._create_backend(data_dir) as backend:
            if not self.auto_unseal and not auth_file.exists():
                if not auto_setup:
                    raise VoidVaultError(f"Vault is not initialized in {data_dir}")
                backend.setup_account(passphrase)
            if not self.auto_unseal:
                backend.unlock(passphrase)
            try:
                token = backend.issue_token(
                    self.app_id, scope=effective_scope, ttl_seconds=self.ttl_seconds
                )
                yield ScopedSession(
                    backend=backend,
                    app_id=self.app_id,
                    scope=effective_scope,
                    token=token,
                )
            finally:
                backend.lock()

    def recover_account(
        self,
        recovery_key: str,
        new_passphrase: str,
        user_id: Optional[str] = None,
    ) -> None:
        """
        Recovers a locked-out or forgotten-password vault using a one-time
        Emergency Recovery Key (`VVREC-...`) without losing encrypted data.
        """
        data_dir = self._resolve_user_dir(user_id)
        with self._create_backend(data_dir) as backend:
            backend.recover_with_key(recovery_key, new_passphrase)
            backend.lock()

    def verify_audit_log(self, user_id: Optional[str] = None) -> int:
        """Verifies the tamper-evident BLAKE2b-256 audit log chain and returns entry count."""
        data_dir = self._resolve_user_dir(user_id)
        with self._create_backend(data_dir) as backend:
            return backend.verify_audit()

    @staticmethod
    def require_scope(required_scope: str) -> Callable[[F], F]:
        """
        Decorator that enforces a `ScopedSession` argument satisfies `required_scope`
        before executing the decorated function.
        """
        def decorator(func: F) -> F:
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                session_obj: Optional[ScopedSession] = None
                for arg in args:
                    if isinstance(arg, ScopedSession):
                        session_obj = arg
                        break
                if session_obj is None:
                    for val in kwargs.values():
                        if isinstance(val, ScopedSession):
                            session_obj = val
                            break
                if session_obj is None:
                    raise VoidVaultError(
                        f"Function '{func.__name__}' requires a ScopedSession with scope '{required_scope}'"
                    )
                if not _scope_satisfies(session_obj.scope, required_scope):
                    raise VoidVaultError(
                        f"Scope violation in '{func.__name__}': session has '{session_obj.scope}', "
                        f"but '{required_scope}' is required"
                    )
                return func(*args, **kwargs)
            return wrapper  # type: ignore[return-value]
        return decorator
