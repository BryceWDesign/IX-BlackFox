from __future__ import annotations

from dataclasses import dataclass

from ix_blackfox.bus import EventEnvelope, EventTopic
from ix_blackfox.kernel import TaskKind, TaskRecord
from ix_blackfox.packs import (
    BasePack,
    PackCapability,
    PackCapabilityType,
    PackContext,
    PackExecutionResult,
    PackManifest,
)


@dataclass(frozen=True, slots=True)
class ArchitectureDecision:
    """
    One deterministic architecture decision emitted by the architecture pack.

    Attributes
    ----------
    decision_id:
        Stable decision identifier within the generated architecture plan.
    concern:
        Architectural concern being addressed.
    recommendation:
        Recommended architectural direction.
    rationale:
        Why this recommendation was selected.
    """

    decision_id: str
    concern: str
    recommendation: str
    rationale: str

    def __post_init__(self) -> None:
        normalized_decision_id = _normalize_identifier(
            self.decision_id,
            label="decision id",
        )
        normalized_concern = _normalize_identifier(self.concern, label="concern")
        normalized_recommendation = _normalize_text(
            self.recommendation,
            label="recommendation",
        )
        normalized_rationale = _normalize_text(self.rationale, label="rationale")

        object.__setattr__(self, "decision_id", normalized_decision_id)
        object.__setattr__(self, "concern", normalized_concern)
        object.__setattr__(self, "recommendation", normalized_recommendation)
        object.__setattr__(self, "rationale", normalized_rationale)


class ArchitecturePack(BasePack):
    """
    Built-in pack for architecture-oriented tasks.

    This first version stays deterministic and explicit. It does not invent
    full system diagrams on its own. Instead it converts architecture prompts
    into stable design decisions that later planning and documentation layers
    can build on.
    """

    @property
    def pack_name(self) -> str:
        return "architecture"

    def execute(
        self,
        *,
        task: TaskRecord,
        context: PackContext,
    ) -> PackExecutionResult:
        prompt = task.request.input.prompt
        decisions = self._derive_decisions(prompt)
        summary = self._build_summary(decisions)

        context.shared_state.put(
            "packs",
            "last_executed",
            self.pack_name,
            source=self.pack_name,
        )
        context.shared_state.put(
            "architecture",
            "last_task_id",
            task.request.task_id,
            source=self.pack_name,
        )
        context.shared_state.put(
            "architecture",
            "last_decision_count",
            len(decisions),
            source=self.pack_name,
        )

        context.bus.publish(
            EventEnvelope.create(
                topic=EventTopic.PACK,
                source=self.pack_name,
                correlation_id=task.request.task_id,
                payload={
                    "pack": self.pack_name,
                    "task_id": task.request.task_id,
                    "decision_count": len(decisions),
                    "concerns": tuple(decision.concern for decision in decisions),
                },
                tags=("pack", "architecture", "design"),
            )
        )

        return PackExecutionResult(
            summary=summary,
            artifacts=("architecture-plan.json",),
            metrics={
                "decision_count": len(decisions),
                "has_boundary_decision": any(
                    decision.concern == "system-boundary" for decision in decisions
                ),
                "has_interface_decision": any(
                    decision.concern == "interface-surface" for decision in decisions
                ),
            },
            data={
                "pack": self.pack_name,
                "task_id": task.request.task_id,
                "task_kind": task.request.kind.value,
                "decisions": [
                    {
                        "decision_id": decision.decision_id,
                        "concern": decision.concern,
                        "recommendation": decision.recommendation,
                        "rationale": decision.rationale,
                    }
                    for decision in decisions
                ],
            },
        )

    def _derive_decisions(self, prompt: str) -> tuple[ArchitectureDecision, ...]:
        normalized_prompt = prompt.strip().lower()
        decisions: list[ArchitectureDecision] = []

        decisions.append(
            ArchitectureDecision(
                decision_id="decision-1",
                concern="system-boundary",
                recommendation=(
                    "Define one sovereign runtime boundary before adding external "
                    "adapters or operator surfaces."
                ),
                rationale=(
                    "A stable system boundary prevents architecture drift and keeps "
                    "internal contracts testable."
                ),
            )
        )

        if _contains_any(
            normalized_prompt,
            ("api", "interface", "endpoint", "cli", "ui", "surface"),
        ):
            decisions.append(
                ArchitectureDecision(
                    decision_id=f"decision-{len(decisions) + 1}",
                    concern="interface-surface",
                    recommendation=(
                        "Keep interface layers thin and route all material work "
                        "through the internal kernel contracts."
                    ),
                    rationale=(
                        "Thin interfaces reduce duplication and preserve one source "
                        "of orchestration truth."
                    ),
                )
            )

        if _contains_any(
            normalized_prompt,
            ("memory", "state", "persistence", "context"),
        ):
            decisions.append(
                ArchitectureDecision(
                    decision_id=f"decision-{len(decisions) + 1}",
                    concern="state-model",
                    recommendation=(
                        "Separate working, episodic, semantic, artifact, and trace "
                        "state instead of flattening everything into one store."
                    ),
                    rationale=(
                        "Tiered state keeps retrieval behavior explicit and reduces "
                        "cross-layer coupling."
                    ),
                )
            )

        if _contains_any(
            normalized_prompt,
            ("security", "policy", "guardrail", "vault", "audit"),
        ):
            decisions.append(
                ArchitectureDecision(
                    decision_id=f"decision-{len(decisions) + 1}",
                    concern="trust-boundary",
                    recommendation=(
                        "Bind sensitive operations to explicit policy checks, "
                        "provenance, and integrity-checked state."
                    ),
                    rationale=(
                        "Architectural trust boundaries must be enforceable and "
                        "auditable, not implied."
                    ),
                )
            )

        if _contains_any(
            normalized_prompt,
            ("performance", "latency", "scale", "throughput", "optimize"),
        ):
            decisions.append(
                ArchitectureDecision(
                    decision_id=f"decision-{len(decisions) + 1}",
                    concern="performance-path",
                    recommendation=(
                        "Profile critical execution paths before introducing complex "
                        "optimization layers."
                    ),
                    rationale=(
                        "Measurement-first performance work avoids architecture "
                        "changes based on guesswork."
                    ),
                )
            )

        if len(decisions) == 1:
            decisions.append(
                ArchitectureDecision(
                    decision_id="decision-2",
                    concern="module-separation",
                    recommendation=(
                        "Separate orchestration, execution, evaluation, and "
                        "observability into explicit modules."
                    ),
                    rationale=(
                        "Clear module boundaries reduce accidental coupling and make "
                        "future extensions safer."
                    ),
                )
            )

        return tuple(decisions)

    def _build_summary(self, decisions: tuple[ArchitectureDecision, ...]) -> str:
        concern_text = ", ".join(decision.concern for decision in decisions)
        return (
            f"Architecture pack prepared {len(decisions)} deterministic decision(s): "
            f"{concern_text}."
        )


def build_architecture_manifest() -> PackManifest:
    """
    Build the manifest for the built-in architecture pack.
    """
    return PackManifest(
        pack_name="architecture",
        version="0.1.0",
        description=(
            "Deterministic architecture pack for system boundaries, module "
            "separation, interface shaping, state design, and trust boundaries."
        ),
        supported_kinds=(TaskKind.ARCHITECTURE, TaskKind.ANALYSIS),
        labels=("design", "architecture", "boundary", "state", "interfaces"),
        capabilities=(
            PackCapability(
                name="boundary planning",
                capability_type=PackCapabilityType.REASONING,
                description="Produces explicit system-boundary recommendations.",
            ),
            PackCapability(
                name="state architecture",
                capability_type=PackCapabilityType.REASONING,
                description="Shapes tiered state and memory boundaries.",
            ),
            PackCapability(
                name="trust modeling",
                capability_type=PackCapabilityType.VALIDATION,
                description="Flags the need for auditable trust boundaries.",
            ),
        ),
        dependencies=(),
        entrypoint="ix_blackfox.packs.architecture.runtime:ArchitecturePack",
        is_default=False,
    )


def _contains_any(text: str, terms: tuple[str, ...]) -> bool:
    return any(term in text for term in terms)


def _normalize_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ValueError(f"Architecture pack {label} must not be empty.")
    return cleaned


def _normalize_text(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"Architecture pack {label} must not be empty.")
    return cleaned
