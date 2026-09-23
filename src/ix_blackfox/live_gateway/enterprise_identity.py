from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

import jwt
from jwt import InvalidTokenError, PyJWKSet

from ix_blackfox.operating.models import digest_payload, normalize_identifier


@dataclass(frozen=True, slots=True)
class OidcProvider:
    issuer: str
    audience: str
    jwks_path: Path
    algorithms: tuple[str, ...] = ("RS256",)
    max_token_age_seconds: int = 900
    clock_skew_seconds: int = 30

    def __post_init__(self) -> None:
        if not self.issuer.strip() or not self.audience.strip():
            raise ValueError("OIDC issuer and audience must not be empty.")
        if not self.algorithms:
            raise ValueError("OIDC provider requires at least one allowed algorithm.")
        if any(algorithm.lower() == "none" for algorithm in self.algorithms):
            raise ValueError("OIDC provider must not allow the 'none' algorithm.")
        if self.max_token_age_seconds <= 0 or self.clock_skew_seconds < 0:
            raise ValueError("OIDC token age must be positive and clock skew non-negative.")


@dataclass(frozen=True, slots=True)
class IdentityBinding:
    issuer: str
    subject: str
    agent_id: str

    def __post_init__(self) -> None:
        if not self.issuer.strip() or not self.subject.strip():
            raise ValueError("Identity binding issuer and subject must not be empty.")
        object.__setattr__(self, "agent_id", normalize_identifier(self.agent_id, label="agent_id"))


@dataclass(frozen=True, slots=True)
class DelegationScope:
    delegation_id: str
    delegated_by: str
    tools: tuple[str, ...]
    repositories: tuple[str, ...]
    path_roots: tuple[str, ...]
    expires_at: int

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> DelegationScope:
        delegation_id = str(value.get("delegation_id", "")).strip()
        delegated_by = str(value.get("delegated_by", "")).strip()
        if not delegation_id or not delegated_by:
            raise ValueError("Every delegation requires delegation_id and delegated_by.")
        tools = _string_tuple(value.get("tools", ()))
        repositories = _string_tuple(value.get("repositories", ()))
        path_roots = tuple(_normalize_path_root(item) for item in _string_tuple(value.get("path_roots", ())))
        expires_at = int(value.get("expires_at", 0))
        if expires_at <= 0:
            raise ValueError("Every delegation requires a positive expires_at timestamp.")
        return cls(
            delegation_id=delegation_id,
            delegated_by=delegated_by,
            tools=tools,
            repositories=repositories,
            path_roots=path_roots,
            expires_at=expires_at,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "delegation_id": self.delegation_id,
            "delegated_by": self.delegated_by,
            "tools": list(self.tools),
            "repositories": list(self.repositories),
            "path_roots": list(self.path_roots),
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    agent_id: str
    authentication_type: str
    issuer: str = ""
    subject: str = ""
    audience: str = ""
    key_id: str = ""
    token_id: str = ""
    issued_at: int = 0
    expires_at: int = 0
    delegation_chain: tuple[DelegationScope, ...] = ()

    @property
    def context_digest(self) -> str:
        return digest_payload(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "authentication_type": self.authentication_type,
            "issuer": self.issuer,
            "subject": self.subject,
            "audience": self.audience,
            "key_id": self.key_id,
            "token_id": self.token_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "delegation_chain": [item.to_dict() for item in self.delegation_chain],
        }

    def authorize_action(self, *, tool_name: str, repository_id: str, path: str) -> str:
        for scope in self.delegation_chain:
            if scope.tools and tool_name not in scope.tools:
                return f"Delegation {scope.delegation_id!r} does not authorize tool {tool_name!r}."
            if scope.repositories and repository_id not in scope.repositories:
                return (
                    f"Delegation {scope.delegation_id!r} does not authorize repository "
                    f"{repository_id!r}."
                )
            if scope.path_roots and not any(_path_within(path, root) for root in scope.path_roots):
                return f"Delegation {scope.delegation_id!r} does not authorize path {path!r}."
        return ""


class IdentityRevocationStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS revoked_credentials (kind TEXT NOT NULL, value TEXT NOT NULL, revoked_at TEXT NOT NULL, reason TEXT NOT NULL, PRIMARY KEY(kind, value))"
            )

    def revoke(self, *, kind: str, value: str, reason: str = "operator_revoked") -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO revoked_credentials(kind, value, revoked_at, reason) VALUES (?, ?, ?, ?)",
                (kind, value, datetime.now(tz=UTC).isoformat(), reason),
            )

    def is_revoked(self, *, kind: str, value: str) -> bool:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT 1 FROM revoked_credentials WHERE kind = ? AND value = ? LIMIT 1",
                (kind, value),
            ).fetchone()
        return row is not None


@dataclass(slots=True)
class FederatedIdentityVerifier:
    providers: tuple[OidcProvider, ...]
    bindings: tuple[IdentityBinding, ...]
    revocations: IdentityRevocationStore

    def verify(self, token: str, *, claimed_agent_id: str = "") -> tuple[AuthenticatedPrincipal | None, str]:
        try:
            unverified_header = jwt.get_unverified_header(token)
            unverified_claims = jwt.decode(token, options={"verify_signature": False})
        except InvalidTokenError:
            return None, "Federated identity token is malformed."
        issuer = str(unverified_claims.get("iss", ""))
        provider = next((item for item in self.providers if item.issuer == issuer), None)
        if provider is None:
            return None, "Federated identity token issuer is not trusted."
        algorithm = str(unverified_header.get("alg", ""))
        key_id = str(unverified_header.get("kid", ""))
        if algorithm not in provider.algorithms or not key_id:
            return None, "Federated identity token algorithm or key id is not permitted."
        try:
            jwks = PyJWKSet.from_json(provider.jwks_path.read_text(encoding="utf-8"))
            matches = [key for key in jwks.keys if key.key_id == key_id]
            if len(matches) != 1:
                return None, "Federated identity signing key is unknown or ambiguous."
            claims = jwt.decode(
                token,
                key=matches[0].key,
                algorithms=list(provider.algorithms),
                audience=provider.audience,
                issuer=provider.issuer,
                leeway=provider.clock_skew_seconds,
                options={"require": ["iss", "sub", "aud", "exp", "iat", "nbf", "jti"]},
            )
        except (InvalidTokenError, OSError, ValueError, json.JSONDecodeError):
            return None, "Federated identity token failed cryptographic or claim validation."
        now = int(datetime.now(tz=UTC).timestamp())
        issued_at = int(claims["iat"])
        expires_at = int(claims["exp"])
        token_id = str(claims["jti"]).strip()
        subject = str(claims["sub"]).strip()
        if not token_id or not subject:
            return None, "Federated identity token subject and token id must not be empty."
        if issued_at > now + provider.clock_skew_seconds:
            return None, "Federated identity token issued-at time is in the future."
        if now - issued_at > provider.max_token_age_seconds + provider.clock_skew_seconds:
            return None, "Federated identity token exceeds the configured maximum credential age."
        if self.revocations.is_revoked(kind="jti", value=token_id):
            return None, "Federated identity token has been revoked."
        binding = next(
            (item for item in self.bindings if item.issuer == issuer and item.subject == subject),
            None,
        )
        if binding is None:
            return None, "Federated identity subject is not bound to a registered BlackFox agent."
        if claimed_agent_id and normalize_identifier(claimed_agent_id, label="agent_id") != binding.agent_id:
            return None, "Authenticated federated identity does not match the claimed agent id."
        try:
            chain = _parse_delegation_chain(claims.get("blackfox_delegation", ()), now=now)
        except ValueError as exc:
            return None, str(exc)
        for delegation in chain:
            if self.revocations.is_revoked(kind="delegation", value=delegation.delegation_id):
                return None, f"Delegation {delegation.delegation_id!r} has been revoked."
        return (
            AuthenticatedPrincipal(
                agent_id=binding.agent_id,
                authentication_type="oidc_jwt",
                issuer=issuer,
                subject=subject,
                audience=provider.audience,
                key_id=key_id,
                token_id=token_id,
                issued_at=issued_at,
                expires_at=expires_at,
                delegation_chain=chain,
            ),
            "",
        )


def _parse_delegation_chain(value: Any, *, now: int) -> tuple[DelegationScope, ...]:
    if value in (None, "", ()):
        return ()
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        raise ValueError("blackfox_delegation must be an ordered array of delegation objects.")
    chain: list[DelegationScope] = []
    for raw in value:
        if not isinstance(raw, Mapping):
            raise ValueError("Every blackfox_delegation entry must be an object.")
        scope = DelegationScope.from_mapping(raw)
        if scope.expires_at <= now:
            raise ValueError(f"Delegation {scope.delegation_id!r} is expired.")
        if chain:
            parent = chain[-1]
            if scope.delegated_by != parent.delegation_id:
                raise ValueError(
                    f"Delegation {scope.delegation_id!r} is not linked to parent "
                    f"{parent.delegation_id!r}."
                )
            _assert_narrower(scope.tools, parent.tools, label="tools", delegation_id=scope.delegation_id)
            _assert_narrower(scope.repositories, parent.repositories, label="repositories", delegation_id=scope.delegation_id)
            if parent.path_roots and any(
                not any(_path_within(child_root, parent_root) for parent_root in parent.path_roots)
                for child_root in scope.path_roots
            ):
                raise ValueError(
                    f"Delegation {scope.delegation_id!r} expands path authority beyond its parent."
                )
            if scope.expires_at > parent.expires_at:
                raise ValueError(
                    f"Delegation {scope.delegation_id!r} expires after its parent delegation."
                )
        chain.append(scope)
    return tuple(chain)


def _assert_narrower(child: tuple[str, ...], parent: tuple[str, ...], *, label: str, delegation_id: str) -> None:
    if parent and (not child or not set(child).issubset(parent)):
        raise ValueError(f"Delegation {delegation_id!r} expands {label} authority beyond its parent.")


def _string_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        raise ValueError("Delegation scope values must be arrays of strings.")
    result = tuple(str(item).strip() for item in value if str(item).strip())
    if len(result) != len(set(result)):
        raise ValueError("Delegation scope values must not contain duplicates.")
    return result


def _normalize_path_root(value: str) -> str:
    candidate = value.strip().replace("\\", "/").strip("/")
    if not candidate or candidate == ".":
        return ""
    path = PurePosixPath(candidate)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("Delegation path roots must be safe relative paths.")
    return path.as_posix()


def _path_within(path: str, root: str) -> bool:
    normalized_path = path.strip().replace("\\", "/").strip("/")
    normalized_root = root.strip().replace("\\", "/").strip("/")
    if not normalized_root:
        return True
    return normalized_path == normalized_root or normalized_path.startswith(normalized_root + "/")
