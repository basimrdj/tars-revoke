from __future__ import annotations

from enum import Enum

import pytest

from tars_revoke.domain.transitions import (
    TRANSITION_TABLES,
    can_transition,
    ensure_transition,
    terminal_states,
)
from tars_revoke.errors import TransitionError


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (current, target)
        for table in TRANSITION_TABLES.values()
        for current, targets in table.items()
        for target in targets
    ],
)
def test_every_declared_transition_is_accepted(current: Enum, target: Enum) -> None:
    assert can_transition(current, target)
    ensure_transition(current, target)


@pytest.mark.parametrize("table", list(TRANSITION_TABLES.values()))
def test_every_undeclared_transition_is_rejected(table) -> None:
    states = tuple(table)
    for current in states:
        for target in states:
            if current == target or target in table[current]:
                continue
            assert not can_transition(current, target)
            with pytest.raises(TransitionError, match="illegal"):
                ensure_transition(current, target)


@pytest.mark.parametrize("table", list(TRANSITION_TABLES.values()))
def test_terminal_states_have_no_exit(table) -> None:
    for state in terminal_states(table):
        assert table[state] == frozenset()


def test_cross_enum_and_same_state_are_not_implicit_transitions() -> None:
    enum_types = list(TRANSITION_TABLES)
    left = next(iter(enum_types[0]))
    right = next(iter(enum_types[1]))

    assert not can_transition(left, right)
    assert not can_transition(left, left)
    assert can_transition(left, left, allow_same=True)
