"""Docker image and container lifecycle for the PyGhidra worker."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from winbox.config import Config
from winbox.kdbg.decomp.client import WORKER_API


GHIDRA_VERSION = "12.1.3"
PYGHIDRA_VERSION = "3.1.0"
PLATFORM = "linux/amd64"
IMAGE = f"winbox-pyghidra:{GHIDRA_VERSION}-{PYGHIDRA_VERSION}-api{WORKER_API}"
COMPONENT_LABEL = "io.winbox.component=pyghidra"


class DockerError(RuntimeError):
    """The managed PyGhidra image or container could not be operated."""


def _state_root(cfg: Config) -> Path:
    return Path(cfg.winbox_dir).expanduser().absolute() / "decomp"


def _state_id(cfg: Config) -> str:
    return hashlib.sha256(os.fsencode(str(_state_root(cfg)))).hexdigest()[:16]


def container_name(cfg: Config) -> str:
    return f"winbox-ghidra-{os.getuid()}-{_state_id(cfg)}"


def project_dir(cfg: Config) -> Path:
    return _state_root(cfg) / "projects"


@contextlib.contextmanager
def _lifecycle_lock(cfg: Config):
    root = _state_root(cfg)
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    with (root / "docker-lifecycle.lock").open("a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class DockerManager:
    """Own exactly one labelled, rootless-as-caller worker container."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.name = container_name(cfg)

    def _docker(
        self, *args: str, timeout: float = 60.0, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        if shutil.which("docker") is None:
            raise DockerError("Docker CLI is not installed or not on PATH")
        try:
            result = subprocess.run(
                ["docker", *args], text=True, capture_output=True,
                timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise DockerError(f"docker {' '.join(args[:2])} timed out") from exc
        except OSError as exc:
            raise DockerError(f"could not run Docker: {exc}") from exc
        if check and result.returncode:
            detail = (result.stderr or result.stdout).strip()
            raise DockerError(
                f"docker {' '.join(args[:2])} failed: {detail or f'exit {result.returncode}'}"
            )
        return result

    def image_info(self) -> dict[str, Any] | None:
        result = self._docker("image", "inspect", IMAGE, timeout=15, check=False)
        if result.returncode:
            detail = (result.stderr or result.stdout).strip()
            if "No such image" in detail or "No such object" in detail:
                return None
            raise DockerError(f"could not inspect Docker image: {detail or 'unknown error'}")
        try:
            values = json.loads(result.stdout)
            info = values[0]
        except (json.JSONDecodeError, IndexError, TypeError) as exc:
            raise DockerError("Docker returned malformed image metadata") from exc
        labels = ((info.get("Config") or {}).get("Labels") or {})
        expected = {
            "io.winbox.component": "pyghidra",
            "io.winbox.worker-api": WORKER_API,
            "io.winbox.ghidra-version": GHIDRA_VERSION,
            "io.winbox.pyghidra-version": PYGHIDRA_VERSION,
        }
        if any(labels.get(key) != value for key, value in expected.items()):
            raise DockerError(f"image {IMAGE} is not an exact winbox service image")
        return {
            "id": info.get("Id"), "created": info.get("Created"),
            "ghidra_version": labels.get("io.winbox.ghidra-version"),
            "pyghidra_version": labels.get("io.winbox.pyghidra-version"),
        }

    def container_info(self) -> dict[str, Any] | None:
        result = self._docker("container", "inspect", self.name, timeout=15, check=False)
        if result.returncode:
            detail = (result.stderr or result.stdout).strip()
            if "No such container" in detail or "No such object" in detail:
                return None
            raise DockerError(
                f"could not inspect PyGhidra container: {detail or 'unknown error'}"
            )
        try:
            values = json.loads(result.stdout)
            info = values[0]
        except (json.JSONDecodeError, IndexError, TypeError) as exc:
            raise DockerError("Docker returned malformed container metadata") from exc
        labels = ((info.get("Config") or {}).get("Labels") or {})
        expected = {
            "io.winbox.component": "pyghidra",
            "io.winbox.state": _state_id(self.cfg),
            "io.winbox.owner-uid": str(os.getuid()),
        }
        if any(labels.get(key) != value for key, value in expected.items()):
            raise DockerError(
                f"refusing to manage unowned container with reserved name {self.name}"
            )
        state = info.get("State") or {}
        return {
            "id": str(info.get("Id") or "")[:12],
            "image_id": info.get("Image"),
            "running": bool(state.get("Running")),
            "status": state.get("Status"),
            "started_at": state.get("StartedAt"),
            "image": (info.get("Config") or {}).get("Image"),
        }

    def status(self) -> dict[str, Any]:
        available = shutil.which("docker") is not None
        result: dict[str, Any] = {
            "backend": "docker", "docker_available": available,
            "image": IMAGE, "container": self.name,
            "image_installed": False, "container_running": False,
            "configured_ghidra_version": GHIDRA_VERSION,
            "pyghidra_version": PYGHIDRA_VERSION,
            "worker_api": WORKER_API,
            "platform": PLATFORM,
        }
        if not available:
            result["error"] = "Docker CLI is not installed or not on PATH"
            return result
        try:
            image = self.image_info()
            container = self.container_info()
            result["image_installed"] = image is not None
            result["image_info"] = image
            result["container_info"] = container
            result["container_running"] = bool(container and container["running"])
        except DockerError as exc:
            result["error"] = str(exc)
        return result

    def install(self, *, pull: bool = True) -> dict[str, Any]:
        with _lifecycle_lock(self.cfg):
            return self._install(pull=pull)

    def _install(self, *, pull: bool) -> dict[str, Any]:
        dockerfile = Path(__file__).with_name("container") / "Dockerfile"
        worker = Path(__file__).with_name("worker.py")
        if not dockerfile.is_file() or not worker.is_file():
            raise DockerError("installed winbox package is missing its Docker build assets")
        root = _state_root(self.cfg)
        root.mkdir(parents=True, exist_ok=True)
        log_path = root / "docker-build.log"
        with tempfile.TemporaryDirectory(prefix="winbox-ghidra-build-") as temporary:
            context = Path(temporary)
            shutil.copyfile(dockerfile, context / "Dockerfile")
            shutil.copyfile(worker, context / "worker.py")
            command = ["build"]
            if pull:
                command.append("--pull")
            command.extend(["--platform", PLATFORM, "--tag", IMAGE, str(context)])
            result = self._docker(*command, timeout=1800, check=False)
            log_path.write_text(
                result.stdout + ("\n" if result.stdout and result.stderr else "") + result.stderr,
                encoding="utf-8",
            )
            if result.returncode:
                tail = (result.stderr or result.stdout)[-3000:].strip()
                raise DockerError(f"Docker image build failed: {tail}; full log: {log_path}")
        info = self.image_info()
        if info is None:
            raise DockerError("Docker reported success but the image is missing")
        return {"installed": True, "image": IMAGE, "log": str(log_path), **info}

    def start(self, *, wait_seconds: float = 45.0) -> dict[str, Any]:
        with _lifecycle_lock(self.cfg):
            return self._start(wait_seconds=wait_seconds)

    def _start(self, *, wait_seconds: float) -> dict[str, Any]:
        image = self.image_info()
        if image is None:
            raise DockerError(
                f"PyGhidra image is not installed; run `winbox kdbg ghidra install`"
            )
        root = _state_root(self.cfg)
        socket = root / "decomp.sock"
        existing = self.container_info()
        if (
            existing and existing["running"] and existing["image"] == IMAGE
            and existing.get("image_id") == image.get("id")
        ):
            if socket.is_socket():
                return {"started": False, "already_running": True, **existing}
            # Docker can report the PID alive briefly after the worker has
            # acknowledged shutdown and removed its socket. Wait for that
            # state transition instead of returning a phantom live service.
            transition = time.monotonic() + min(10.0, max(1.0, wait_seconds))
            while time.monotonic() < transition:
                time.sleep(0.05)
                existing = self.container_info()
                if socket.is_socket():
                    return {"started": False, "already_running": True, **existing}
                if existing is None or not existing["running"]:
                    break
            if existing and existing["running"]:
                raise DockerError(
                    "PyGhidra container is running but its API socket is missing"
                )
        if existing:
            if existing["running"]:
                self._docker("stop", "--timeout", "15", self.name, timeout=30)
            self._docker("rm", self.name, timeout=30)

        cache = root / "cache"
        projects = project_dir(self.cfg)
        for path in (root, cache, projects):
            path.mkdir(parents=True, exist_ok=True)
            os.chmod(path, 0o700)
            if any(character in str(path) for character in (",", "\n", "\r")):
                raise DockerError(
                    f"Docker bind-mount path contains an unsupported character: {path}"
                )
        for stale in (root / "decomp.sock", root / "decomp.session.json"):
            try:
                stale.unlink()
            except FileNotFoundError:
                pass

        uid, gid = os.getuid(), os.getgid()
        command = [
            "run", "--detach", "--platform", PLATFORM, "--name", self.name,
            "--label", COMPONENT_LABEL,
            "--label", f"io.winbox.state={_state_id(self.cfg)}",
            "--label", f"io.winbox.owner-uid={uid}",
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "512",
            "--user", f"{uid}:{gid}",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,mode=1777,size=512m",
            "--mount", f"type=bind,src={root},dst=/run/winbox",
            "--mount", f"type=bind,src={cache},dst=/cache",
            "--mount", f"type=bind,src={projects},dst=/projects",
            IMAGE,
            "--socket", "/run/winbox/decomp.sock",
            "--lock", "/run/winbox/decomp.lock",
            "--session", "/run/winbox/decomp.session.json",
            "--cache", "/cache", "--projects", "/projects",
            "--ghidra-install-dir", "/opt/ghidra",
            "--backend", "docker",
        ]
        self._docker(*command, timeout=60)
        deadline = time.monotonic() + max(1.0, wait_seconds)
        while time.monotonic() < deadline:
            info = self.container_info()
            if info is None or not info["running"]:
                logs = self.logs(tail=100)
                raise DockerError(f"PyGhidra container exited during startup: {logs}")
            if socket.is_socket():
                return {"started": True, **info}
            time.sleep(0.05)
        raise DockerError(
            f"PyGhidra container did not create its API socket within {wait_seconds:g}s"
        )

    def stop(self) -> dict[str, Any]:
        with _lifecycle_lock(self.cfg):
            return self._stop()

    def _stop(self) -> dict[str, Any]:
        existing = self.container_info()
        if existing is None:
            return {"stopped": False, "already_stopped": True}
        if existing["running"]:
            self._docker("stop", "--timeout", "20", self.name, timeout=40)
        self._docker("rm", self.name, timeout=30)
        root = _state_root(self.cfg)
        for stale in (root / "decomp.sock", root / "decomp.session.json"):
            try:
                stale.unlink()
            except FileNotFoundError:
                pass
        return {"stopped": True, "container": self.name}

    def logs(self, *, tail: int = 100) -> str:
        result = self._docker(
            "logs", "--tail", str(max(1, min(int(tail), 1000))), self.name,
            timeout=15, check=False,
        )
        return (result.stdout + result.stderr)[-16000:].strip()
