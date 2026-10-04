"""What a capability says to the model, and whether that has changed.

A name is not consent to whatever a server later puts behind it. A server can
keep an approved tool's name and rewrite its description to steer the model, or
add an argument to carry data out. So the definition is recorded when a person
approves it, and held to that record from then on.
"""

from __future__ import annotations

import functools
import json
import re
import uuid
from collections.abc import Iterable, Iterator, Mapping
from decimal import Decimal
from typing import Any

from jsonschema import Draft202012Validator, validators
from jsonschema.exceptions import SchemaError, best_match
from referencing import Registry

#: Left out of a definition: servers stamp these per build, the model does not
#: read them, and a record that churns teaches people to ignore its diff. Every
#: other field is kept, so the next field the spec adds is covered by default.
UNRECORDED = frozenset({"_meta", "icons"})


def definition_of(item: Mapping[str, Any]) -> dict[str, Any]:
    """The parts of a listed tool, prompt or resource that are held to the record."""

    return {field: value for field, value in item.items() if field not in UNRECORDED}


def changed_fields(recorded: Mapping[str, Any], live: Mapping[str, Any]) -> list[str]:
    """The top-level fields that differ, compared regardless of key order.

    Compared as canonical JSON rather than with ``==``, which in Python reads
    ``true`` and ``1`` as the same value. Numbers compare by value, as JSON has
    one number type: a recorder that wrote ``1.0`` as ``1`` changed nothing.
    """

    fields = (set(recorded) | set(live)) - UNRECORDED
    return sorted(field for field in fields if _canonical(recorded, field) != _canonical(live, field))


def _canonical(definition: Mapping[str, Any], field: str) -> str | None:
    # A field that is absent and one that is null are different definitions.
    if field not in definition:
        return None
    return json.dumps(_numbers_by_value(definition[field]), sort_keys=True, separators=(",", ":"))


def _numbers_by_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _numbers_by_value(inner) for key, inner in value.items()}
    if isinstance(value, list):
        return [_numbers_by_value(inner) for inner in value]
    if isinstance(value, Decimal):
        # A record holds what a JSON parser made of it, so a live number is
        # compared the same way.
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


class ExactNumber(Decimal):
    """A JSON number with a fraction or exponent, kept as written.

    A float would round ``9007199254740993e0`` to ``...992`` and
    ``1.0000000000000001`` to ``1.0``: what this checked would not be what an
    upstream parsing exactly acts on, and a rewritten answer would change the
    caller's data. Integers need nothing, because Python's are exact.
    """

    text: str

    def __new__(cls, text: str) -> ExactNumber:
        number = super().__new__(cls, text)
        number.text = text
        return number


def loads_exact(text: str | bytes, **options: Any) -> Any:
    """JSON with every number exact."""

    return json.loads(text, parse_float=ExactNumber, **options)


def dumps_exact(value: Any) -> str:
    """JSON with every number written as it was read."""

    numbers: list[str] = []
    marker = uuid.uuid4().hex

    def number(value: Any) -> str:
        if not isinstance(value, Decimal):
            raise TypeError(f"{type(value).__name__} is not JSON serialisable")
        numbers.append(value.text if isinstance(value, ExactNumber) else str(value))
        return f"{marker}:{len(numbers) - 1}"

    text = json.dumps(value, default=number)
    if not numbers:
        return text
    return re.sub(f'"{marker}:(\\d+)"', lambda found: numbers[int(found.group(1))], text)


def schema_error(schema: Mapping[str, Any], instance: Any) -> str | None:
    """Why ``instance`` does not satisfy ``schema``, or ``None`` when it does.

    Draft 2020-12 unless the schema names another in ``$schema``. A schema this
    cannot check against is reported as a failure: it cannot vouch for anything.

    References resolve inside the schema and nowhere else. The default resolver
    fetches any URL a ``$ref`` names, which would let an upstream's definition
    point this process at its own network, and block it while it waits.
    """

    try:
        cls = validators.validator_for(schema, default=Draft202012Validator)
        cls.check_schema(schema)
        validator = _exact(cls)(_decimals(schema), registry=_NOTHING_REMOTE)
        error = best_match(validator.iter_errors(instance))
    except SchemaError as failure:
        return f"the recorded schema could not be checked (invalid schema: {failure.message})"
    except Exception as failure:  # an unresolvable $ref, or a schema the validator chokes on
        reason = (str(failure).splitlines() or [""])[0][:200] or failure.__class__.__name__
        return f"the recorded schema could not be checked ({reason})"
    # Messages render an exact number as Decimal('...'); a person reads the number.
    return None if error is None else re.sub(r"(?:Exact[A-Za-z]*|Decimal)\('([^']*)'\)", r"\1", str(error.message))


@functools.cache
def _exact(cls: Any) -> Any:
    """``cls`` with an exact integral number counted as an integer, where floats like ``1.0`` are."""

    checker = cls.TYPE_CHECKER
    if not checker.is_type(1.0, "integer"):
        return cls  # draft 4 and earlier: 1.0 is not an integer, and neither is its exact form
    integer = functools.partial(checker.is_type, type="integer")
    return validators.extend(
        cls,
        type_checker=checker.redefine(
            "integer",
            lambda _, value: integer(value)
            or (isinstance(value, Decimal) and value.is_finite() and value == value.to_integral_value()),
        ),
    )


def _decimals(value: Any) -> Any:
    """A schema with its floats exact, so bounds compare with exact numbers without rounding either."""

    if isinstance(value, float):
        return Decimal(repr(value))
    if isinstance(value, Mapping):
        return {key: _decimals(inner) for key, inner in value.items()}
    if isinstance(value, list):
        return [_decimals(inner) for inner in value]
    return value


#: Retrieves nothing: a reference outside the schema itself is unresolvable.
_NOTHING_REMOTE: Registry[Any] = Registry()


#: Characters a person reviewing the text cannot see but a model reads:
#: zero-width and joiner characters, bidirectional overrides that reorder what
#: is displayed, and the Unicode tag block, which can spell out a whole hidden
#: sentence. U+200D, the zero-width joiner, is left out: it holds family and
#: flag emoji together, and flagging it would flag honest output.
INVISIBLE = re.compile("[\u200b\u200c\u200e\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]")

#: Wording seen in published tool-poisoning attacks: text addressed to the model
#: rather than describing the tool. A short list on purpose. It flags text for a
#: closer read and decides nothing, and a long list would flag honest output
#: until nobody reads the flag.
ADDRESSED_TO_MODEL = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"ignore (all |any )?(previous|prior|above) (instructions|prompts)",
        r"</?(important|system|instructions?)>",
        r"do not (tell|inform|mention|alert|notify) the user",
        r"without (telling|informing|asking) the user",
        r"\bid_rsa\b|~/\.ssh|\.aws/credentials",
    )
]


def suspicious(texts: Iterable[str]) -> list[str]:
    """Why some text deserves a closer read before a model acts on it, if it does."""

    texts = list(texts)
    reasons: list[str] = []
    if any(INVISIBLE.search(text) for text in texts):
        reasons.append("contains invisible characters")
    if any(pattern.search(text) for pattern in ADDRESSED_TO_MODEL for text in texts):
        reasons.append("contains text addressed to the model")
    return reasons


def strings_in(value: Any) -> Iterator[str]:
    """Every string in a JSON value, keys included."""

    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, inner in value.items():
            yield str(key)
            yield from strings_in(inner)
    elif isinstance(value, list):
        for inner in value:
            yield from strings_in(inner)
