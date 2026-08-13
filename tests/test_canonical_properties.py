"""Property tests for idempotency key derivation.

This is the load-bearing piece. If two calls that mean the same thing derive different
keys, a retry pays twice. If two calls that mean different things derive the same key, a
legitimate action is silently swallowed and reported as a duplicate. Every other guarantee
sits on top of this function behaving.

Example-based tests only cover the collisions someone thought of, so these generate them.
"""

from __future__ import annotations

import math
from decimal import Decimal

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from airlock.core.canonical import canonical, encode, idempotency_key
from airlock.core.idempotency import derive_key

# Anything a tool argument can plausibly be after pydantic has validated it.
scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(10**12), max_value=10**12),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    st.text(max_size=40),
)
values = st.recursive(
    scalars,
    lambda inner: st.one_of(
        st.lists(inner, max_size=4),
        st.dictionaries(st.text(min_size=1, max_size=12), inner, max_size=4),
    ),
    max_leaves=12,
)
arguments = st.dictionaries(st.text(min_size=1, max_size=12), values, max_size=5)


@given(arguments)
@settings(max_examples=250, deadline=None)
def test_the_same_arguments_always_derive_the_same_key(args: dict) -> None:
    assert idempotency_key("pay", args, "inv-1") == idempotency_key("pay", args, "inv-1")


@given(arguments)
@settings(max_examples=250, deadline=None)
def test_argument_order_never_changes_the_key(args: dict) -> None:
    """Two clients serialising the same call must not disagree about what it is."""
    reversed_args = dict(reversed(list(args.items())))
    assert idempotency_key("pay", args, "i") == idempotency_key("pay", reversed_args, "i")


@given(arguments, st.text(min_size=1, max_size=20), st.text(min_size=1, max_size=20))
@settings(max_examples=250, deadline=None)
def test_different_intents_never_share_a_key(args: dict, first: str, second: str) -> None:
    assume(first != second)
    assert idempotency_key("pay", args, first) != idempotency_key("pay", args, second)


@given(arguments, st.text(min_size=1, max_size=12), st.text(min_size=1, max_size=12))
@settings(max_examples=250, deadline=None)
def test_different_tools_never_share_a_key(args: dict, first: str, second: str) -> None:
    assume(first != second)
    assert idempotency_key(first, args, "i") != idempotency_key(second, args, "i")


@given(arguments, arguments)
@settings(max_examples=400, deadline=None)
def test_different_arguments_never_share_a_key(first: dict, second: dict) -> None:
    """The dangerous direction: a collision means a real action is swallowed as a retry."""
    assume(encode(first) != encode(second))
    assert idempotency_key("pay", first, "i") != idempotency_key("pay", second, "i")


@given(st.integers(min_value=-(10**9), max_value=10**9))
@settings(max_examples=200, deadline=None)
def test_a_whole_number_is_the_same_however_it_is_spelled(number: int) -> None:
    """An LLM emits 40, a JSON client emits 40.0, a form emits "40"."""
    keys = {
        idempotency_key("pay", {"amount": spelling}, "i")
        for spelling in (number, float(number), str(number), Decimal(number))
    }
    assert len(keys) == 1


@given(
    st.decimals(
        allow_nan=False,
        allow_infinity=False,
        places=2,
        min_value=Decimal("-1e9"),
        max_value=Decimal("1e9"),
    )
)
@settings(max_examples=200, deadline=None)
def test_trailing_zeros_do_not_change_an_amount(amount: Decimal) -> None:
    assert idempotency_key("pay", {"amount": amount}, "i") == idempotency_key(
        "pay", {"amount": Decimal(f"{amount:.6f}")}, "i"
    )


@given(st.floats(allow_nan=False, allow_infinity=False, width=32))
@settings(max_examples=200, deadline=None)
def test_canonicalising_a_number_is_reversible_in_value(number: float) -> None:
    assert math.isclose(float(canonical(number)), number, rel_tol=1e-9, abs_tol=1e-12)


@given(st.text(max_size=40))
@settings(max_examples=200, deadline=None)
def test_visually_identical_unicode_agrees(text: str) -> None:
    import unicodedata

    decomposed = unicodedata.normalize("NFD", text)
    assert idempotency_key("pay", {"to": text}, "i") == idempotency_key(
        "pay", {"to": decomposed}, "i"
    )


@given(arguments, st.dictionaries(st.text(min_size=1, max_size=8), scalars, max_size=3))
@settings(max_examples=200, deadline=None)
def test_context_stays_out_of_the_key_unless_opted_in(args: dict, context: dict) -> None:
    assert derive_key("pay", args, "i", context) == derive_key("pay", args, "i", {})


@given(st.dictionaries(st.text(min_size=1, max_size=8), scalars, min_size=1, max_size=3))
@settings(max_examples=200, deadline=None)
def test_an_opted_in_context_field_does_change_the_key(context: dict) -> None:
    field = next(iter(context))
    assume(context[field] is not None)
    other = dict(context, **{field: "a different value entirely"})
    assume(encode(context[field]) != encode(other[field]))
    assert derive_key("pay", {}, "i", context, [field]) != derive_key(
        "pay", {}, "i", other, [field]
    )


@given(values)
@settings(max_examples=250, deadline=None)
def test_canonical_output_is_always_encodable(value: object) -> None:
    assert isinstance(encode(value), str)


def test_a_non_finite_amount_is_refused_rather_than_hashed() -> None:
    """NaN is not equal to itself, so it must never reach a key."""
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(TypeError):
            canonical(bad)
