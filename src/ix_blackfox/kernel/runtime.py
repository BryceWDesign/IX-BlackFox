from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum, auto
from threading import RLock
from uuid import uuid4

from ix_blackfox.config import RuntimeConfig, load_runtime_config


class KernelStatus(StrEnum):
    """
    Lifecycle states for the BlackFox kernel.
    """

    CREATED = auto()
    INITIALIZING = auto()
    READY = auto()
    RUNNING = auto()
    STOPPING = auto()
    STOPPED = auto()


@dataclass(frozen=True, slots=True)
class KernelSnapshot:
    """
    Immutable runtime view of the kernel state.

    Attributes
    ----------
    kernel_id:
        Unique identifier for this kernel instance.
    status:
        Current lifecycle status.
    environment:
        Runtime environment string from configuration.
    debug:
        Debug mode flag.
    started_at:
        UTC timestamp when the kernel entered RUNNING, if any.
    stopped_at:
        UTC timestamp when the kernel entered STOPPED, if any.
    """

    kernel_id: str
    status: KernelStatus
    environment: str
    debug: bool
    started_at: datetime | None
    stopped_at: datetime | None


class BlackFoxKernel:
    """
    Foundational runtime kernel for IX-BlackFox.

    This first version intentionally focuses on lifecycle correctness and
    controlled state transitions. Task graphs, scheduling, event flow, and
    subsystem wiring will layer on top of this core rather than being mixed
    into boot logic from the start.
    """

    def __init__(self, config: RuntimeConfig) -> None:
        self._config = config
        self._kernel_id = f"bfk-{uuid4().hex}"
        self._status = KernelStatus.CREATED
        self._started_at: datetime | None = None
        self._stopped_at: datetime | None = None
        self._lock = RLock()

    @classmethod
    def from_default_config(cls) -> BlackFoxKernel:
        """
        Build a kernel using the default runtime configuration loader.
        """
        return cls(load_runtime_config())

    @property
    def kernel_id(self) -> str:
        """
        Stable identifier for this kernel instance.
        """
        return self._kernel_id

    @property
    def status(self) -> KernelStatus:
        """
        Current kernel lifecycle state.
        """
        with self._lock:
            return self._status

    @property
    def config(self) -> RuntimeConfig:
        """
        Bound runtime configuration for this kernel instance.
        """
        return self._config

    def initialize(self) -> None:
        """
        Prepare the kernel runtime.

        This creates expected runtime directories and transitions the kernel
        into the READY state. It is safe to call more than once once the
        kernel is already READY or RUNNING.
        """
        with self._lock:
            if self._status in {KernelStatus.READY, KernelStatus.RUNNING}:
                return

            if self._status in {KernelStatus.STOPPING, KernelStatus.STOPPED}:
                raise RuntimeError(
                    "Cannot initialize a kernel that is stopping or stopped."
                )

            self._status = KernelStatus.INITIALIZING
            self._config.paths.ensure_exists()
            self._status = KernelStatus.READY

    def start(self) -> None:
        """
        Transition the kernel into the RUNNING state.

        If the kernel has not been initialized yet, initialization is
        performed automatically.
        """
        with self._lock:
            if self._status == KernelStatus.RUNNING:
                return

            if self._status in {KernelStatus.STOPPING, KernelStatus.STOPPED}:
                raise RuntimeError("Cannot start a kernel that is stopping or stopped.")

        self.initialize()

        with self._lock:
            self._started_at = _utc_now()
            self._stopped_at = None
            self._status = KernelStatus.RUNNING

    def stop(self) -> None:
        """
        Transition the kernel into the STOPPED state.
        """
        with self._lock:
            if self._status == KernelStatus.STOPPED:
                return

            if self._status == KernelStatus.CREATED:
                self._status = KernelStatus.STOPPED
                self._stopped_at = _utc_now()
                return

            self._status = KernelStatus.STOPPING
            self._stopped_at = _utc_now()
            self._status = KernelStatus.STOPPED

    def snapshot(self) -> KernelSnapshot:
        """
        Produce an immutable view of the current kernel state.
        """
        with self._lock:
            return KernelSnapshot(
                kernel_id=self._kernel_id,
                status=self._status,
                environment=self._config.environment,
                debug=self._config.debug,
                started_at=self._started_at,
                stopped_at=self._stopped_at,
            )

    def is_ready(self) -> bool:
        """
        Return True when the kernel is capable of accepting work.
        """
        with self._lock:
            return self._status in {KernelStatus.READY, KernelStatus.RUNNING}


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)
