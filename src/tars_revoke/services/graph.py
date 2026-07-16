from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from tars_revoke.errors import ValidationError


def _enum_value(value: object) -> str:
    raw = getattr(value, "value", value)
    return str(raw).lower()


def _field(record: object, *names: str) -> Any:
    if isinstance(record, Mapping):
        for name in names:
            if name in record:
                return record[name]
    for name in names:
        if hasattr(record, name):
            return getattr(record, name)
    raise ValidationError(f"record is missing required field: {'/'.join(names)}")


def _optional_field(record: object, *names: str, default: Any = None) -> Any:
    try:
        return _field(record, *names)
    except ValidationError:
        return default


@dataclass(frozen=True)
class DependencyPath:
    """One persisted causal path from the invalidated root to a dependent."""

    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]

    @property
    def root_id(self) -> str:
        return self.node_ids[0]

    @property
    def dependent_id(self) -> str:
        return self.node_ids[-1]


@dataclass(frozen=True)
class ClosureResult:
    root_id: str
    scope: str
    dependent_ids: tuple[str, ...]
    paths: tuple[DependencyPath, ...]

    def is_reachable(self, node_id: str) -> bool:
        return node_id in self.dependent_ids

    def path_to(self, node_id: str) -> DependencyPath | None:
        return next((path for path in self.paths if path.dependent_id == node_id), None)


class TypedCausalGraph:
    """Cycle-safe, scope-aware reachability over typed dependency edges.

    Enforcement intentionally considers only ``hard requires`` edges.  Models,
    embeddings, similarity scores, and free-form explanations never participate
    in the traversal.
    """

    def __init__(self, edges: Iterable[object] = ()) -> None:
        self._edges: list[object] = []
        for edge in edges:
            self.add_edge(edge)

    @property
    def edges(self) -> tuple[object, ...]:
        return tuple(self._edges)

    def add_edge(self, edge: object) -> None:
        source = str(_field(edge, "from_node_id", "source_node_id", "source_id"))
        target = str(_field(edge, "to_node_id", "target_node_id", "target_id"))
        if not source or not target:
            raise ValidationError("dependency edge endpoints must be non-empty")
        if source == target:
            raise ValidationError("self dependencies are not admissible")
        _field(edge, "edge_type", "kind", "type")
        _field(edge, "strength")
        self._edges.append(edge)

    def hard_closure(self, root_id: str, *, scope: str) -> ClosureResult:
        if not root_id:
            raise ValidationError("root_id is required")
        if not scope:
            raise ValidationError("scope is required")

        adjacency: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for edge in self._edges:
            if _enum_value(_field(edge, "edge_type", "kind", "type")) != "requires":
                continue
            if _enum_value(_field(edge, "strength")) != "hard":
                continue
            edge_scope = str(_optional_field(edge, "scope", default=""))
            if edge_scope != scope:
                continue
            source = str(_field(edge, "from_node_id", "source_node_id", "source_id"))
            target = str(_field(edge, "to_node_id", "target_node_id", "target_id"))
            edge_id = str(_optional_field(edge, "id", "edge_id", default=f"{source}->{target}"))
            adjacency[source].append((target, edge_id))

        # Sorting makes receipts and tests stable even when persistence returns
        # rows in a different order.
        for outgoing in adjacency.values():
            outgoing.sort(key=lambda item: (item[0], item[1]))

        queue: deque[str] = deque([root_id])
        visited = {root_id}
        parent: dict[str, tuple[str, str]] = {}

        while queue:
            source = queue.popleft()
            for target, edge_id in adjacency.get(source, ()):
                if target in visited:
                    continue
                visited.add(target)
                parent[target] = (source, edge_id)
                queue.append(target)

        dependents = tuple(sorted(visited - {root_id}))
        paths: list[DependencyPath] = []
        for dependent_id in dependents:
            node_ids = [dependent_id]
            edge_ids: list[str] = []
            cursor = dependent_id
            while cursor != root_id:
                predecessor, edge_id = parent[cursor]
                node_ids.append(predecessor)
                edge_ids.append(edge_id)
                cursor = predecessor
            paths.append(
                DependencyPath(
                    node_ids=tuple(reversed(node_ids)),
                    edge_ids=tuple(reversed(edge_ids)),
                )
            )

        return ClosureResult(
            root_id=root_id,
            scope=scope,
            dependent_ids=dependents,
            paths=tuple(paths),
        )

    def is_reachable(self, root_id: str, dependent_id: str, *, scope: str) -> bool:
        return self.hard_closure(root_id, scope=scope).is_reachable(dependent_id)


def compute_hard_closure(
    root_id: str,
    edges: Iterable[object],
    *,
    scope: str,
) -> ClosureResult:
    """Convenience entry point used by persistence and property tests."""

    return TypedCausalGraph(edges).hard_closure(root_id, scope=scope)
