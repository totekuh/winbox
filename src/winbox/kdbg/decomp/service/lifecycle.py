"""Worker lifecycle: status, install, start, stop, cancel."""

from __future__ import annotations

from typing import Any

from winbox.config import Config
from winbox.kdbg.decomp.client import DecompClient, DecompError
from winbox.kdbg.decomp.service.prepare_bg import cancel_prepare_job


def _wrapped_decomp_error(prefix: str, exc: BaseException) -> DecompError:
    return DecompError(
        f"{prefix}: {getattr(exc, 'message', exc)}",
        code=getattr(exc, "code", None),
        retryable=bool(getattr(exc, "retryable", False)),
        details=getattr(exc, "details", {}),
    )


def worker_status(cfg: Config) -> dict[str, Any]:
    return DecompClient(cfg).status()


def cancel_decomp(
    cfg: Config, *, request_id: str = "", token: str = "",
) -> dict[str, Any]:
    if request_id and token:
        raise DecompError(
            "request_id and token are mutually exclusive", code="invalid_argument",
        )
    if token:
        return cancel_prepare_job(cfg, token=token)
    return DecompClient(cfg).cancel(request_id)


def install_service(cfg: Config, *, pull: bool = True) -> dict[str, Any]:
    """Build the pinned, self-contained PyGhidra image."""
    from winbox.kdbg.decomp.docker import DockerError, DockerManager

    try:
        return DockerManager(cfg).install(pull=pull)
    except DockerError as exc:
        raise DecompError(str(exc)) from exc


def start_service(cfg: Config) -> dict[str, Any]:
    """Start the private Unix-socket API without loading the JVM yet."""
    from winbox.kdbg.decomp.docker import DockerError, DockerManager

    manager = DockerManager(cfg)
    try:
        if manager.image_info() is None:
            raise DockerError(
                "PyGhidra image is not installed; run `winbox kdbg ghidra install`"
            )
        DecompClient(cfg).ensure_selected_backend()
        result = manager.start()
    except DockerError as exc:
        raise DecompError(str(exc)) from exc
    status = DecompClient(cfg).call("status", start=False, timeout=10.0)
    return {**result, "api": status}


def stop_service(cfg: Config) -> dict[str, Any]:
    """Stop and remove only the precisely labelled winbox container."""
    from winbox.kdbg.decomp.docker import DockerError, DockerManager

    try:
        return DockerManager(cfg).stop()
    except DockerError as exc:
        raise DecompError(str(exc)) from exc
