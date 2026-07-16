from __future__ import annotations

from dataclasses import dataclass

import pytest

from tars_revoke.errors import ValidationError
from tars_revoke.services.graph import TypedCausalGraph, compute_hard_closure


@dataclass(frozen=True)
class Edge:
    id: str
    from_node_id: str
    to_node_id: str
    edge_type: str = "requires"
    strength: str = "hard"
    scope: str = "repo:billing"


def test_hard_closure_finds_three_dependents_without_fixture_ids_in_runtime() -> None:
    root = "premise:customer-id"
    effects = ["effect:migration", "effect:model", "effect:push"]
    graph = TypedCausalGraph(
        Edge(f"edge:{index}", root, effect_id)
        for index, effect_id in enumerate(effects)
    )

    closure = graph.hard_closure(root, scope="repo:billing")

    assert set(closure.dependent_ids) == set(effects)
    assert {path.dependent_id for path in closure.paths} == set(effects)
    assert all(path.root_id == root for path in closure.paths)


def test_unrelated_agent_is_negative_reachability_and_soft_or_foreign_edges_do_not_leak() -> None:
    edges = [
        Edge("e1", "premise:p", "plan:a"),
        Edge("e2", "plan:a", "effect:a"),
        Edge("soft", "premise:p", "effect:agent-b", strength="soft"),
        Edge("foreign", "premise:p", "effect:other-repo", scope="repo:other"),
        Edge("support", "premise:p", "effect:support", edge_type="supports"),
    ]

    closure = compute_hard_closure("premise:p", edges, scope="repo:billing")

    assert closure.dependent_ids == ("effect:a", "plan:a")
    assert not closure.is_reachable("effect:agent-b")
    assert not closure.is_reachable("effect:other-repo")
    assert not closure.is_reachable("effect:support")
    assert closure.path_to("effect:a").node_ids == (
        "premise:p",
        "plan:a",
        "effect:a",
    )


def test_cycles_are_safe_and_each_dependent_has_a_stable_shortest_path() -> None:
    edges = [
        Edge("e1", "p", "a"),
        Edge("e2", "a", "b"),
        Edge("e3", "b", "a"),
        Edge("e4", "p", "b"),
    ]

    closure = compute_hard_closure("p", edges, scope="repo:billing")

    assert closure.dependent_ids == ("a", "b")
    assert closure.path_to("b").node_ids == ("p", "b")


def test_self_dependency_is_rejected() -> None:
    graph = TypedCausalGraph()
    with pytest.raises(ValidationError, match="self dependencies"):
        graph.add_edge(Edge("bad", "same", "same"))


def test_wildcard_scope_does_not_cross_the_persisted_scope_boundary() -> None:
    graph = TypedCausalGraph(
        [
            Edge("exact", "p", "effect:exact"),
            Edge("wildcard", "p", "effect:wildcard", scope="*"),
        ]
    )

    closure = graph.hard_closure("p", scope="repo:billing")

    assert closure.dependent_ids == ("effect:exact",)
