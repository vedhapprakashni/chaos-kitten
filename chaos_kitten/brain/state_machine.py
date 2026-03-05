"""Multi-Step State Machine Agent for Chaos Kitten.

Detects business-logic vulnerabilities that only appear when multiple API
endpoints are invoked in a specific (or illegal) order.  The agent:

1. **Maps relationships** between endpoints by analysing path patterns and
   HTTP methods (CRUD heuristics + optional LLM refinement).
2. **Builds state chains** — ordered sequences such as
   ``POST /orders  →  GET /orders/{id}  →  DELETE /orders/{id}``.
3. **Executes state-breaking tests**:
   - *Broken-flow*: skip required steps (e.g. checkout without payment).
   - *Cross-user IDOR*: resource created by User A is accessed by User B.
   - *Out-of-order*: invoke steps in the wrong sequence.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class EndpointNode:
    """Single endpoint in a state chain."""
    method: str
    path: str
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    request_body: Optional[Dict[str, Any]] = None

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.path}"


@dataclass
class StateChain:
    """An ordered sequence of endpoint calls representing a workflow."""
    name: str
    resource: str
    steps: List[EndpointNode] = field(default_factory=list)
    description: str = ""

    def step_keys(self) -> List[str]:
        return [s.key for s in self.steps]


@dataclass
class StateFinding:
    """A vulnerability discovered during state-chain testing."""
    finding_type: str  # broken_flow | idor | out_of_order
    chain_name: str
    description: str
    severity: str
    evidence: str
    endpoint: str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.finding_type,
            "name": f"State Machine: {self.finding_type.replace('_', ' ').title()}",
            "chain": self.chain_name,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
            "endpoint": self.endpoint,
            "recommendation": self.recommendation,
        }


# ---------------------------------------------------------------------------
# Relationship mapper (rule-based)
# ---------------------------------------------------------------------------

# Matches path templates like /users/{id}, /orders/{order_id}
_PARAM_RE = re.compile(r"\{(\w+)\}")


def _extract_resource(path: str) -> Optional[str]:
    """Extract the primary resource name from a path.

    ``/api/v1/orders/{id}/items`` → ``orders``
    ``/users`` → ``users``
    """
    segments = [s for s in path.split("/") if s and not _PARAM_RE.fullmatch(s)]
    # Skip common prefixes
    skip = {"api", "v1", "v2", "v3", "rest"}
    meaningful = [s for s in segments if s.lower() not in skip]
    return meaningful[0] if meaningful else None


def _is_parameterised(path: str) -> bool:
    return bool(_PARAM_RE.search(path))


class RelationshipMapper:
    """Maps CRUD relationships between endpoints using path heuristics."""

    # Method ordering in a typical CRUD lifecycle
    CRUD_ORDER = {"POST": 0, "GET": 1, "PUT": 2, "PATCH": 3, "DELETE": 4}

    def map(self, endpoints: List[Dict[str, Any]]) -> List[StateChain]:
        """Group endpoints by resource and build state chains.

        Returns one ``StateChain`` per resource that has ≥2 related
        endpoints.
        """
        # Group by resource
        resource_map: Dict[str, List[EndpointNode]] = {}
        for ep in endpoints:
            path = ep.get("path", "")
            method = ep.get("method", "GET").upper()
            resource = _extract_resource(path)
            if not resource:
                continue
            node = EndpointNode(
                method=method,
                path=path,
                parameters=ep.get("parameters", []),
                request_body=ep.get("requestBody"),
            )
            resource_map.setdefault(resource, []).append(node)

        chains: List[StateChain] = []
        for resource, nodes in resource_map.items():
            if len(nodes) < 2:
                continue
            # Sort by CRUD order
            nodes.sort(key=lambda n: self.CRUD_ORDER.get(n.method, 99))
            chain = StateChain(
                name=f"{resource}_crud",
                resource=resource,
                steps=nodes,
                description=f"CRUD lifecycle for /{resource}",
            )
            chains.append(chain)

        return chains


# ---------------------------------------------------------------------------
# State-breaking test executor
# ---------------------------------------------------------------------------

class StateMachineAgent:
    """Execute state-chain disruption tests.

    Parameters
    ----------
    base_url : str
        Target application base URL.
    executor : object
        An initialised ``Executor`` instance (with ``execute_attack``).
    auth_token_b : str | None
        An optional *second* auth token representing a different user,
        used for cross-user IDOR tests.
    """

    def __init__(
        self,
        base_url: str = "",
        executor: Any = None,
        auth_token_b: Optional[str] = None,
    ) -> None:
        self.base_url = base_url
        self.executor = executor
        self.auth_token_b = auth_token_b

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyse(
        self, endpoints: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Full pipeline: map → build chains → run tests → return findings."""
        mapper = RelationshipMapper()
        chains = mapper.map(endpoints)

        if not chains:
            logger.info("No state chains detected — skipping state tests.")
            return []

        logger.info("Detected %d state chain(s): %s",
                     len(chains), [c.name for c in chains])

        findings: List[StateFinding] = []

        for chain in chains:
            findings.extend(await self._test_broken_flow(chain))
            findings.extend(await self._test_out_of_order(chain))
            if self.auth_token_b:
                findings.extend(await self._test_idor(chain))

        return [f.to_dict() for f in findings]

    # ------------------------------------------------------------------
    # Test strategies
    # ------------------------------------------------------------------

    async def _test_broken_flow(self, chain: StateChain) -> List[StateFinding]:
        """Skip intermediate steps and jump to a later step.

        For example, calling ``DELETE /orders/{id}`` without first calling
        ``POST /orders`` to create the resource.
        """
        findings: List[StateFinding] = []
        if len(chain.steps) < 2:
            return findings

        # Strategy: call the LAST step directly without executing earlier steps
        last = chain.steps[-1]
        path = _PARAM_RE.sub("1", last.path)  # substitute params with "1"

        resp = await self._execute(last.method, path)
        if resp and self._is_success(resp):
            findings.append(StateFinding(
                finding_type="broken_flow",
                chain_name=chain.name,
                description=(
                    f"Endpoint {last.key} succeeded without prior steps "
                    f"({' → '.join(chain.step_keys())})"
                ),
                severity="high",
                evidence=f"Status {resp.get('status_code')} on direct call",
                endpoint=last.key,
                recommendation=(
                    "Enforce server-side state validation. Ensure that "
                    "dependent operations verify prerequisite state before "
                    "execution."
                ),
            ))

        # Strategy: skip middle steps (for chains with ≥3 steps)
        if len(chain.steps) >= 3:
            first = chain.steps[0]
            last = chain.steps[-1]
            # Execute first, skip middle, execute last
            first_path = _PARAM_RE.sub("1", first.path)
            resp_first = await self._execute(first.method, first_path, payload={"test": "state"})

            if resp_first and self._is_success(resp_first):
                # Try to extract an ID from the response
                resource_id = self._extract_id(resp_first)
                last_path = _PARAM_RE.sub(
                    str(resource_id) if resource_id else "1", last.path
                )
                resp_last = await self._execute(last.method, last_path)
                if resp_last and self._is_success(resp_last):
                    findings.append(StateFinding(
                        finding_type="broken_flow",
                        chain_name=chain.name,
                        description=(
                            f"Skipped intermediate steps in {chain.name} — "
                            f"jumped from {first.key} directly to {last.key}"
                        ),
                        severity="medium",
                        evidence=(
                            f"First: status {resp_first.get('status_code')}, "
                            f"Last: status {resp_last.get('status_code')}"
                        ),
                        endpoint=last.key,
                        recommendation=(
                            "Add workflow state checks on the server side "
                            "to prevent skipping required steps."
                        ),
                    ))

        return findings

    async def _test_out_of_order(self, chain: StateChain) -> List[StateFinding]:
        """Execute steps in reverse order to detect missing state guards."""
        findings: List[StateFinding] = []
        if len(chain.steps) < 2:
            return findings

        reversed_steps = list(reversed(chain.steps))
        # Execute the would-be LAST step first (e.g. DELETE before POST)
        step = reversed_steps[0]
        path = _PARAM_RE.sub("99999", step.path)  # non-existent resource

        resp = await self._execute(step.method, path)
        if resp and self._is_success(resp):
            findings.append(StateFinding(
                finding_type="out_of_order",
                chain_name=chain.name,
                description=(
                    f"{step.key} succeeded on a likely non-existent resource "
                    f"(out-of-order execution)"
                ),
                severity="medium",
                evidence=f"Status {resp.get('status_code')} for id=99999",
                endpoint=step.key,
                recommendation=(
                    "Return 404 for non-existent resources and validate "
                    "resource state before destructive operations."
                ),
            ))
        return findings

    async def _test_idor(self, chain: StateChain) -> List[StateFinding]:
        """Cross-user IDOR: User A creates → User B reads/deletes.

        Requires ``auth_token_b`` to be set for the second user.
        """
        findings: List[StateFinding] = []
        if not self.auth_token_b:
            return findings

        # Find the POST (create) and a GET (read) step
        create_step = next(
            (s for s in chain.steps if s.method == "POST" and not _is_parameterised(s.path)),
            None,
        )
        read_step = next(
            (s for s in chain.steps if s.method == "GET" and _is_parameterised(s.path)),
            None,
        )
        if not create_step or not read_step:
            return findings

        # User A creates
        resp_create = await self._execute(
            create_step.method, create_step.path,
            payload={"test": "idor_probe"},
        )
        if not resp_create or not self._is_success(resp_create):
            return findings

        resource_id = self._extract_id(resp_create)
        if not resource_id:
            return findings

        # User B tries to read using User A's ID
        read_path = _PARAM_RE.sub(str(resource_id), read_step.path)
        resp_read = await self._execute(
            read_step.method, read_path,
            headers={"Authorization": f"Bearer {self.auth_token_b}"},
        )
        if resp_read and self._is_success(resp_read):
            findings.append(StateFinding(
                finding_type="idor",
                chain_name=chain.name,
                description=(
                    f"User B accessed User A's resource at {read_step.key} "
                    f"with id={resource_id}"
                ),
                severity="critical",
                evidence=(
                    f"Create: status {resp_create.get('status_code')}, "
                    f"Cross-read: status {resp_read.get('status_code')}"
                ),
                endpoint=read_step.key,
                recommendation=(
                    "Implement resource-level authorisation checks. "
                    "Ensure users can only access their own resources."
                ),
            ))
        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _execute(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Thin wrapper around ``executor.execute_attack``."""
        if not self.executor:
            logger.warning("No executor configured — skipping %s %s", method, path)
            return None
        try:
            return await self.executor.execute_attack(
                method=method,
                path=path,
                payload=payload,
                headers=headers,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("State machine request failed: %s %s — %s", method, path, exc)
            return None

    @staticmethod
    def _is_success(resp: Dict[str, Any]) -> bool:
        code = resp.get("status_code", 0)
        return 200 <= code < 300

    @staticmethod
    def _extract_id(resp: Dict[str, Any]) -> Optional[str]:
        """Try to pull a resource ID from the response body."""
        body = resp.get("body", "")
        if isinstance(body, str):
            try:
                data = json.loads(body)
            except (json.JSONDecodeError, TypeError):
                data = {}
        elif isinstance(body, dict):
            data = body
        else:
            return None

        # Try common ID field names
        for key in ("id", "ID", "_id", "resource_id", "order_id", "user_id"):
            if key in data:
                return str(data[key])
        return None
