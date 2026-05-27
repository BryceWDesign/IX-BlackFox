from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from ix_blackfox.authoring import (
    PatchAuthoringPromptContract,
    PromptMessageRole,
)
from ix_blackfox.brains import (
    BrainInvocationRequest,
    BrainInvocationStatus,
    BrainMessage,
    BrainModality,
    BrainRole,
)
from ix_blackfox.brains.manifest import BrainManifest
from ix_blackfox.brains.providers import (
    BrainProvider,
    BrainProviderInvocation,
)
from ix_blackfox.runtime.authoring_repair import PatchProposalProvider


@dataclass(frozen=True, slots=True)
class BrainPatchProposalProvider(PatchProposalProvider):
    """
    Adapter from Wave 7 brain providers into Wave 3 patch proposal generation.

    The adapter gives the authored-repair runtime a provider-neutral model source
    while preserving the existing BlackFox boundary: models may only return raw
    JSON patch proposals. They still cannot edit files, run commands, approve
    review, or claim test success.
    """

    provider: BrainProvider
    manifest: BrainManifest
    role: BrainRole = BrainRole.PRIMARY
    timeout_seconds: float | None = None
    labels: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.provider.supports_manifest(self.manifest):
            raise ValueError(
                "BrainPatchProposalProvider provider_name must match manifest.provider_name."
            )
        if not self.manifest.supports_role(self.role):
            raise ValueError(
                "BrainPatchProposalProvider role must be supported by the manifest."
            )
        if not self.manifest.accepts_modality(BrainModality.TEXT):
            raise ValueError(
                "BrainPatchProposalProvider requires a text-capable manifest."
            )
        object.__setattr__(self, "labels", _normalize_labels(self.labels))
        object.__setattr__(self, "metadata", dict(self.metadata))
        if self.timeout_seconds is not None and self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero when provided.")

    @property
    def provider_name(self) -> str:
        """
        Return the provider name recorded by authoring receipts.
        """
        return self.provider.provider_name

    @property
    def model_name(self) -> str:
        """
        Return the manifest model name recorded by authoring receipts.
        """
        return self.manifest.model_name

    def generate(self, contract: PatchAuthoringPromptContract) -> Iterable[str]:
        """
        Invoke the configured brain provider and return raw proposal JSON.
        """
        invocation = self.build_invocation(contract)
        response = self.provider.invoke(invocation)

        if response.result.status is not BrainInvocationStatus.SUCCEEDED:
            return ()

        output_text = response.result.output_text
        if output_text is None:
            return ()

        cleaned = output_text.strip()
        if not cleaned:
            return ()

        return (cleaned,)

    def build_invocation(
        self,
        contract: PatchAuthoringPromptContract,
    ) -> BrainProviderInvocation:
        """
        Build the provider-neutral invocation submitted to a brain backend.
        """
        request = BrainInvocationRequest.create(
            brain_name=self.manifest.brain_name,
            role=self.role,
            prompt=self._prompt(contract),
            messages=self._messages(contract),
            input_modalities=(BrainModality.TEXT,),
            task_id=contract.request_id,
            pack_name="programming",
            labels=self.labels,
            metadata={
                "runtime": "BrainPatchProposalProvider",
                "wave": 7,
                "authoring_contract_id": contract.contract_id,
                "authoring_contract_digest": contract.digest,
                "authoring_prompt_version": contract.prompt_version,
                "authoring_mode": contract.mode.value,
                "response_schema_version": contract.response_schema.schema_version,
                "response_format": "json",
                **dict(self.metadata),
            },
        )
        return BrainProviderInvocation(
            manifest=self.manifest,
            request=request,
            timeout_seconds=self.timeout_seconds,
            metadata={
                "bridge": "wave7_brain_patch_proposal_provider",
                "contract_id": contract.contract_id,
                "contract_digest": contract.digest,
            },
        )

    def _messages(
        self,
        contract: PatchAuthoringPromptContract,
    ) -> tuple[BrainMessage, ...]:
        return tuple(
            BrainMessage(
                role=_message_role(message.role),
                content=message.content,
                metadata={
                    "authoring_contract_id": contract.contract_id,
                    **dict(message.metadata),
                },
            )
            for message in contract.messages
        )

    def _prompt(self, contract: PatchAuthoringPromptContract) -> str:
        return "\n".join(
            [
                "Generate one raw JSON patch proposal for the supplied IX-BlackFox authoring contract.",
                "Return JSON only. Do not wrap the response in markdown.",
                "Do not claim that tests passed. Do not approve your own proposal.",
                f"Contract id: {contract.contract_id}",
                f"Contract digest: {contract.digest}",
            ]
        )


def _message_role(role: PromptMessageRole) -> str:
    if role is PromptMessageRole.SYSTEM:
        return "system"
    return "user"


def _normalize_labels(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        cleaned = value.strip().lower().replace(" ", "-")
        if not cleaned:
            continue
        if cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return tuple(normalized)
