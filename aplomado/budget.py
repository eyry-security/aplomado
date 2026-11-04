"""Per-host IMR budget for AI scans.

The budget is the real internal cost of a host review: the DeepSeek token
spend reported by each model response, priced with the configured rate card.
It is deliberately separate from the customer-facing credit meter.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Mapping

BUDGET_USD_ENV = "EYRY_AI_SCAN_BUDGET_USD_PER_HOST"
INPUT_MISS_USD_ENV = "EYRY_DEEPSEEK_USD_PER_M_INPUT_MISS"
INPUT_HIT_USD_ENV = "EYRY_DEEPSEEK_USD_PER_M_INPUT_HIT"
OUTPUT_USD_ENV = "EYRY_DEEPSEEK_USD_PER_M_OUTPUT"

DEFAULT_BUDGET_USD = Decimal("1.00")
DEFAULT_INPUT_MISS_USD = Decimal("0.30")
DEFAULT_INPUT_HIT_USD = Decimal("0.006")
DEFAULT_OUTPUT_USD = Decimal("1.20")
MILLION = Decimal(1_000_000)
WRAP_UP_FRACTION = Decimal("0.90")


def _env_decimal(name: str, default: Decimal) -> Decimal:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = Decimal(raw)
    except InvalidOperation:
        return default
    if not value.is_finite() or value < 0:
        return default
    return value


@dataclass(frozen=True)
class RateCard:
    """USD per million tokens for the DeepSeek cache-miss/hit/output split."""

    input_miss_per_million: Decimal
    input_hit_per_million: Decimal
    output_per_million: Decimal

    def __post_init__(self) -> None:
        for name in (
            "input_miss_per_million",
            "input_hit_per_million",
            "output_per_million",
        ):
            object.__setattr__(self, name, Decimal(str(getattr(self, name))))

    @classmethod
    def from_env(cls) -> "RateCard":
        return cls(
            input_miss_per_million=_env_decimal(
                INPUT_MISS_USD_ENV, DEFAULT_INPUT_MISS_USD
            ),
            input_hit_per_million=_env_decimal(
                INPUT_HIT_USD_ENV, DEFAULT_INPUT_HIT_USD
            ),
            output_per_million=_env_decimal(
                OUTPUT_USD_ENV, DEFAULT_OUTPUT_USD
            ),
        )

    def as_dict(self) -> dict[str, str]:
        return {
            "input_miss_per_million_usd": format(
                self.input_miss_per_million, "f"
            ),
            "input_hit_per_million_usd": format(
                self.input_hit_per_million, "f"
            ),
            "output_per_million_usd": format(self.output_per_million, "f"),
        }


@dataclass(frozen=True)
class UsageBreakdown:
    prompt_tokens: int
    cache_miss_tokens: int
    cache_hit_tokens: int
    completion_tokens: int
    cache_split: bool


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _token(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _first_token(*values: Any) -> int | None:
    for value in values:
        parsed = _token(value)
        if parsed is not None:
            return parsed
    return None


def normalize_usage(usage: Any) -> UsageBreakdown:
    """Normalize provider usage into prompt cache-miss/hit/output counts.

    Accepts the raw DeepSeek keys, LangChain's ``usage_metadata`` shape, or a
    Pinnace usage record. When no cache split is present, every prompt token is
    billed at the cache-miss rate.
    """
    data = _mapping(usage)
    prompt = _first_token(
        data.get("prompt_tokens"), data.get("input_tokens")
    ) or 0
    completion = _first_token(
        data.get("completion_tokens"), data.get("output_tokens")
    ) or 0

    miss = _token(data.get("prompt_cache_miss_tokens"))
    hit = _token(data.get("prompt_cache_hit_tokens"))
    if hit is None:
        hit = _token(data.get("cache_read_input_tokens"))
    split = miss is not None or hit is not None

    if not split:
        details = _mapping(data.get("input_token_details"))
        if "cache_read" in details:
            hit = _token(details.get("cache_read")) or 0
            split = True
        else:
            prompt_details = _mapping(data.get("prompt_tokens_details"))
            if "cached_tokens" in prompt_details:
                hit = _token(prompt_details.get("cached_tokens")) or 0
                split = True
            elif "cache_read_tokens" in data:
                hit = _token(data.get("cache_read_tokens")) or 0
                split = True

    if not split:
        miss = prompt
        hit = 0
    else:
        hit = hit or 0
        if miss is None:
            miss = max(prompt - hit, 0)
        prompt = max(prompt, miss + hit)
        if prompt > miss + hit:
            miss += prompt - miss - hit

    return UsageBreakdown(
        prompt_tokens=prompt,
        cache_miss_tokens=miss or 0,
        cache_hit_tokens=hit or 0,
        completion_tokens=completion,
        cache_split=split,
    )


def usage_from_response(response: Any) -> dict[str, Any]:
    """Merge standardized and provider-native usage metadata for one response."""
    standard = _mapping(getattr(response, "usage_metadata", None))
    response_metadata = _mapping(getattr(response, "response_metadata", None))
    native = _mapping(
        response_metadata.get("usage") or response_metadata.get("token_usage")
    )
    merged: dict[str, Any] = dict(native)
    for key, value in standard.items():
        merged.setdefault(key, value)
    additional = _mapping(getattr(response, "additional_kwargs", None))
    for container in ("usage", "token_usage"):
        for key, value in _mapping(additional.get(container)).items():
            merged.setdefault(key, value)
    return merged


def cost_from_usage(usage: Any, rates: RateCard) -> Decimal:
    """True IMR in USD for one usage object."""
    breakdown = normalize_usage(usage)
    numerator = (
        Decimal(breakdown.cache_miss_tokens)
        * rates.input_miss_per_million
        + Decimal(breakdown.cache_hit_tokens)
        * rates.input_hit_per_million
        + Decimal(breakdown.completion_tokens)
        * rates.output_per_million
    )
    return numerator / MILLION


def _money(value: Decimal) -> str:
    rounded = value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return f"${rounded:.2f}"


class ScanBudget:
    """Thread-safe accumulator for one host review's true token cost."""

    def __init__(
        self,
        limit_usd: Decimal | str | int | float = DEFAULT_BUDGET_USD,
        rates: RateCard | None = None,
    ) -> None:
        self.limit_usd = max(Decimal(0), Decimal(str(limit_usd)))
        self.rates = rates or RateCard.from_env()
        self._spent = Decimal(0)
        self._model_calls = 0
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls) -> "ScanBudget":
        return cls(
            limit_usd=_env_decimal(BUDGET_USD_ENV, DEFAULT_BUDGET_USD),
            rates=RateCard.from_env(),
        )

    def record_usage(self, usage: Any) -> Decimal:
        cost = cost_from_usage(usage, self.rates)
        with self._lock:
            self._spent += cost
            self._model_calls += 1
        return cost

    def record_response(self, response: Any) -> Decimal:
        return self.record_usage(usage_from_response(response))

    @property
    def spent(self) -> Decimal:
        with self._lock:
            return self._spent

    @property
    def spent_usd(self) -> float:
        return float(self.spent)

    @property
    def remaining(self) -> Decimal:
        return max(Decimal(0), self.limit_usd - self.spent)

    @property
    def remaining_usd(self) -> float:
        return float(self.remaining)

    @property
    def model_calls(self) -> int:
        with self._lock:
            return self._model_calls

    @property
    def fraction_used(self) -> Decimal:
        if self.limit_usd <= 0:
            return Decimal(1) if self.spent > 0 else Decimal(0)
        return self.spent / self.limit_usd

    @property
    def exhausted(self) -> bool:
        return self.spent >= self.limit_usd

    @property
    def wrap_up(self) -> bool:
        return self.fraction_used >= WRAP_UP_FRACTION

    def snapshot(self) -> dict[str, Any]:
        spent = self.spent
        remaining = max(Decimal(0), self.limit_usd - spent)
        exhausted = spent >= self.limit_usd
        return {
            "limit_usd": float(self.limit_usd),
            "spent_usd": float(spent),
            "remaining_usd": float(remaining),
            "fraction_used": float(
                (spent / self.limit_usd)
                if self.limit_usd > 0
                else (Decimal(1) if spent > 0 else Decimal(0))
            ),
            "model_calls": self.model_calls,
            "exhausted": exhausted,
            "outcome": "budget_exhausted" if exhausted else "completed",
            "rates": self.rates.as_dict(),
        }


def budget_line(
    budget: ScanBudget,
    *,
    completed_turns: int,
    final: bool = False,
) -> str:
    """Build the per-turn budget line, switching to a wrap-up order at 90%."""
    spent = budget.spent
    remaining = max(Decimal(0), budget.limit_usd - spent)
    base = (
        f"[BUDGET] This host review has spent {_money(spent)} of its "
        f"{_money(budget.limit_usd)} budget; {_money(remaining)} remains"
    )

    if final or budget.exhausted:
        return (
            f"{base}. The budget is exhausted. This is the final wrap-up "
            "turn: stop opening new lines of investigation and file "
            "outstanding findings now. Only finish() may be called."
        )

    pacing = ""
    if completed_turns >= 2 and spent > 0:
        average = spent / Decimal(completed_turns)
        if average > 0:
            turns_left = int(
                (remaining / average).to_integral_value(
                    rounding=ROUND_HALF_UP
                )
            )
            pacing = f" (about {turns_left} turns at the recent pace)"

    if budget.wrap_up:
        return (
            f"{base}{pacing}. Wrap up now: stop opening new lines of "
            "investigation and file outstanding findings now."
        )

    return (
        f"{base}{pacing}. File each finding as you confirm it. When the "
        "budget runs out, the review ends."
    )
