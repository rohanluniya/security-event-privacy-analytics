"""Identity resolution mapping email/device/session/token -> pseudonymous principal_token without NAT IP conflation."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from models.contracts import SecurityEvent
from services.secops_platform.privacy import PrivacyVault


@dataclass
class IdentityResolutionEntry:
    principal_token: str
    alias_type: str
    alias_token: str
    subject_key_id: str
    first_seen_ms: int
    last_seen_ms: int
    key_version: str


class IdentityResolver:
    """Resolves multi-stream security identities while strictly prohibiting shared NAT IP conflation.

    Resolution priority:
      1. `actor_email` -> canonical HMAC principal_token (binds device/session/token aliases).
      2. `token_id` -> previously bound principal_token.
      3. `session_id` -> previously bound principal_token.
      4. `device_id` -> previously bound principal_token.
      5. Unbound fallback -> pseudonymous device or session token (NEVER `source_ip`!).
    """

    def __init__(self, vault: PrivacyVault, max_aliases: int = 50_000) -> None:
        self.vault = vault
        self.max_aliases = max_aliases
        self._alias_to_principal: OrderedDict[str, str] = OrderedDict()
        self._resolution_map: dict[tuple[str, str, str], IdentityResolutionEntry] = {}

    def _put_alias(self, alias_key: str, principal_token: str) -> None:
        if alias_key in self._alias_to_principal:
            self._alias_to_principal.move_to_end(alias_key)
        self._alias_to_principal[alias_key] = principal_token
        while len(self._alias_to_principal) > self.max_aliases:
            self._alias_to_principal.popitem(last=False)

    def _record_mapping(
        self,
        principal_token: str,
        alias_type: str,
        alias_token: str,
        event_time_ms: int,
    ) -> None:
        key = (principal_token, alias_type, alias_token)
        subject_key_id = self.vault.ensure_subject_key(principal_token)
        existing = self._resolution_map.get(key)
        if existing is None:
            self._resolution_map[key] = IdentityResolutionEntry(
                principal_token=principal_token,
                alias_type=alias_type,
                alias_token=alias_token,
                subject_key_id=subject_key_id,
                first_seen_ms=event_time_ms,
                last_seen_ms=event_time_ms,
                key_version=self.vault.key_version,
            )
        else:
            existing.first_seen_ms = min(existing.first_seen_ms, event_time_ms)
            existing.last_seen_ms = max(existing.last_seen_ms, event_time_ms)

    def resolve(self, event: SecurityEvent) -> str:
        """Resolve an event to its canonical pseudonymous `principal_token`."""
        dev_tok = self.vault.hmac_token("dev", event.device_id) if event.device_id else None
        ses_tok = self.vault.hmac_token("ses", event.session_id) if event.session_id else None
        tok_hash = self.vault.hmac_token("tok", event.token_id) if event.token_id else None

        principal: str | None = None
        if event.actor_email:
            principal = self.vault.hmac_token("prn", event.actor_email)
        elif tok_hash and f"tok:{tok_hash}" in self._alias_to_principal:
            principal = self._alias_to_principal[f"tok:{tok_hash}"]
        elif ses_tok and f"ses:{ses_tok}" in self._alias_to_principal:
            principal = self._alias_to_principal[f"ses:{ses_tok}"]
        elif dev_tok and f"dev:{dev_tok}" in self._alias_to_principal:
            principal = self._alias_to_principal[f"dev:{dev_tok}"]
        elif dev_tok:
            principal = self.vault.hmac_token("prn_dev", event.device_id or "unknown")
        elif ses_tok:
            principal = self.vault.hmac_token("prn_ses", event.session_id or "unknown")
        else:
            # Never conflate on source_ip; fall back to unique event-scoped anonymous token
            principal = self.vault.hmac_token("prn_anon", event.event_id)

        # Bind aliases to canonical principal (bounded LRU)
        if event.actor_email:
            email_tok = self.vault.hmac_token("eml", event.actor_email)
            self._record_mapping(principal, "email", email_tok, event.event_time_ms)
        if dev_tok and not (event.device_id or "").startswith("dev-bot-"):
            # Do not bind external botnet device IDs to victim employee identities
            self._put_alias(f"dev:{dev_tok}", principal)
            self._record_mapping(principal, "device", dev_tok, event.event_time_ms)
        if ses_tok:
            self._put_alias(f"ses:{ses_tok}", principal)
            self._record_mapping(principal, "session", ses_tok, event.event_time_ms)
        if tok_hash:
            self._put_alias(f"tok:{tok_hash}", principal)
            self._record_mapping(principal, "token", tok_hash, event.event_time_ms)

        return principal

    def export_identity_map_rows(self) -> list[dict[str, Any]]:
        """Export vault-managed identity alias mapping rows for `silver.identity_resolution_map`."""
        return [
            {
                "principal_token": entry.principal_token,
                "alias_type": entry.alias_type,
                "alias_token": entry.alias_token,
                "subject_key_id": entry.subject_key_id,
                "first_seen_ms": entry.first_seen_ms,
                "last_seen_ms": entry.last_seen_ms,
                "key_version": entry.key_version,
            }
            for entry in self._resolution_map.values()
        ]

    @property
    def alias_state_size(self) -> int:
        return len(self._alias_to_principal)
