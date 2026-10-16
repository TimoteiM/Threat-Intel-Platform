"""An aggregate reports its top contributor's share, or it is not an aggregate.

**Sixth instance of a statistic whose dominant term was an artefact**, which is
the point at which noticing stops being a strategy:

| # | the aggregate | the dominant term |
|---|---|---|
| 1 | "every alert carries a manager" | `Manager: Siembiot` on all of them |
| 2 | "the same 14 failures" | one grouping covering none of the set |
| 3 | 5,477 alerts from 100 hosts | `Windows-Test-Device` was 47% |
| 4 | case membership via `ioc_values` | a fact true of every row |
| 5 | 600 recent Falcon alerts, 1 true positive | recency *was* the untriaged family |
| 6 | 2,047 Falcon alerts, 21.9% true positive | **one laptop is 70.4%**, and holds 98% of the true positives |

Instance 6 is the one this module exists for. Held out, the same corpus gives
**2.3%** — an order of magnitude — and nothing in the output of the pooled
figure hinted that a single Windows laptop running `TestingActivity` was most
of it.

The intervention that has actually held today was not a rule, it was a return
type: `falcon_client.Page` made a caller unable to forget that it held a page.
So the same move here. `measure()` returns a `Concentrated`, which carries the
top contributor's share and, above a threshold, **the held-out value computed
alongside** — so a caller cannot report the pooled number without having been
handed the disaggregated one.

This does not decide which figure to publish. A pooled rate is often the right
one. It removes the option of not knowing.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, NamedTuple

#: Above this share, one contributor is enough of the population that the
#: held-out value is computed and carried. 0.25 rather than 0.5: by the time a
#: single term is half the data the figure is openly about that term, and the
#: cases that fooled us were at 47% and 70%.
CONCENTRATION_THRESHOLD = 0.25


class Concentrated(NamedTuple):
    """A measurement, plus what one contributor did to it.

    * `value` — the aggregate over everything.
    * `population` — how many items it was computed over.
    * `top`, `top_share`, `top_count` — the largest contributor.
    * `held_out` — the same aggregate with the top contributor removed, or
      `None` when its share is below the threshold.
    * `held_out_population` — how many items that leaves.
    * `concentrated` — whether the threshold was crossed.

    `sentence()` is the renderable form, because a figure whose concentration
    is known and unstated is no better than one whose concentration is
    unknown — see README rule 23 on an honest producer with an inattentive
    consumer.
    """

    value: Any
    population: int
    top: Any
    top_count: int
    top_share: float
    held_out: Any = None
    held_out_population: int = 0
    concentrated: bool = False

    def sentence(self, *, unit: str = "records", fmt: Callable[[Any], str] = str) -> str:
        if not self.population:
            return f"No {unit} to measure, so there is no figure rather than a zero."
        base = (f"{fmt(self.value)} over {self.population:,} {unit}")
        if not self.concentrated:
            return (f"{base}; the largest single contributor is {self.top!r} at "
                    f"{self.top_share:.0%}, so no one of them dominates it.")
        return (
            f"{base} — but {self.top!r} alone is {self.top_count:,} of them "
            f"({self.top_share:.0%}), and with it held out the same figure is "
            f"{fmt(self.held_out)} over {self.held_out_population:,} {unit}. "
            f"Both are stated because the pooled one is substantially about "
            f"{self.top!r}."
        )


def measure(
    items: Iterable[Any],
    *,
    by: Callable[[Any], Any],
    aggregate: Callable[[list[Any]], Any],
    threshold: float = CONCENTRATION_THRESHOLD,
) -> Concentrated:
    """Compute `aggregate` over `items`, and again without the top `by` group.

    `by` names each item's contributor — a hostname, a tenant, a source. The
    held-out computation uses the **same** `aggregate`, so the two figures are
    comparable by construction rather than by the caller remembering to use
    the same method twice.
    """
    rows = list(items)
    if not rows:
        return Concentrated(aggregate([]), 0, None, 0, 0.0)

    groups: dict[Any, list[Any]] = {}
    for row in rows:
        groups.setdefault(by(row), []).append(row)
    top = max(groups, key=lambda k: len(groups[k]))
    top_count = len(groups[top])
    share = top_count / len(rows)
    value = aggregate(rows)
    if share < threshold:
        return Concentrated(value, len(rows), top, top_count, share)
    rest = [r for r in rows if by(r) != top]
    return Concentrated(
        value, len(rows), top, top_count, share,
        aggregate(rest), len(rest), True,
    )
