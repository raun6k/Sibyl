#!/usr/bin/env python3
"""Charts for the results narrative, in light and dark.

Reads eval/results/eval-full.json and eval/results/robustness.json and
writes PNGs to eval/results/charts/{light,dark}/. The annotated case file
is drawn on output_examples/ui/case.png, which is a dark screenshot, so it
is written once to both folders.

    uv run --with matplotlib eval/charts.py
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch, Rectangle  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "eval" / "results"
OUT = RESULTS / "charts"
CASE_PNG = ROOT / "output_examples" / "ui" / "case.png"

THEMES = {
    "light": {
        "surface": "#fcfcfb",
        "ink": "#0b0b0b",
        "ink2": "#52514e",
        "muted": "#898781",
        "grid": "#e1e0d9",
        "axis": "#c3c2b7",
        "card": "#f3f2ee",
        "accent": "#2a78d6",
        "other": "#b9b7af",
        "series": ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"],
    },
    "dark": {
        "surface": "#1a1a19",
        "ink": "#f0efec",
        "ink2": "#c3c2b7",
        "muted": "#898781",
        "grid": "#2c2c2a",
        "axis": "#383835",
        "card": "#242423",
        "accent": "#3987e5",
        "other": "#5e5d58",
        "series": ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181"],
    },
}
STATUS = {"good": "#0ca30c", "warning": "#fab219", "critical": "#d03b3b"}
# A list in font.family lets matplotlib fall back per glyph (✓ ✗ → are not in Helvetica).
FONT = ["Helvetica Neue", "Arial", "DejaVu Sans"]
BUCKETS = ["straightforward", "nvd_gap", "range_conflict", "text_only", "special"]
BUCKET_NAMES = {
    "straightforward": "Straightforward",
    "nvd_gap": "NVD gap",
    "range_conflict": "Range conflict",
    "text_only": "Text only",
    "special": "Withdrawn / KEV",
}
# Labels for one-column waffle groups, which are too narrow for one line.
STACKED = {"text_only": "Text\nonly", "special": "Withdrawn\n/ KEV"}
SHORT = {
    "B1 NVD-CPE-only": "B1 NVD only",
    "B2 OSV-only": "B2 OSV only",
    "B3 naive union": "B3 union",
    "B4 single-pass LLM": "B4 LLM",
    "Sibyl": "Sibyl",
    "Sibyl − critic": "Sibyl − critic",
    "Sibyl run 2": "Sibyl run 2",
}


def main() -> int:
    result = json.loads((RESULTS / "eval-full.json").read_text(encoding="utf-8"))
    robust = json.loads((RESULTS / "robustness.json").read_text(encoding="utf-8"))
    gold = [json.loads(line) for line in (ROOT / "eval" / "gold" / "gold.jsonl").read_text(encoding="utf-8").splitlines() if line]
    for mode, theme in THEMES.items():
        folder = OUT / mode
        folder.mkdir(parents=True, exist_ok=True)
        plt.rcParams.update(
            {
                "font.family": FONT,
                "text.color": theme["ink"],
                "axes.labelcolor": theme["ink2"],
                "xtick.color": theme["muted"],
                "ytick.color": theme["ink2"],
                "axes.edgecolor": theme["axis"],
                "figure.facecolor": theme["surface"],
                "axes.facecolor": theme["surface"],
                "savefig.facecolor": theme["surface"],
            }
        )
        charts = [
            ("01-problem-recall-by-bucket", recall_by_bucket),
            ("02-gold-set", gold_set),
            ("03-wins", stat_panel),
            ("04-per-pair-grid", per_pair_grid),
            ("05-cost-per-case", cost_per_case),
            ("06-how-each-system-is-wrong", outcome_stack),
            ("08-memory-effect", memory_effect),
            ("09-cpe-join-gap", join_gap),
            ("10-critic-conflicts", critic_conflicts),
            ("11-robustness-outages", outage_matrix),
            ("12-robustness-osv-down", osv_down),
            ("13-robustness-defences", defences),
        ]
        for name, draw in charts:
            figure = draw(theme, result=result, robust=robust, gold=gold)
            figure.savefig(folder / f"{name}.png", dpi=200, bbox_inches="tight", pad_inches=0.35)
            plt.close(figure)
        figure = case_annotated(theme)
        figure.savefig(folder / "07-case-file-validator.png", dpi=150, bbox_inches="tight", pad_inches=0.2)
        plt.close(figure)
        print(f"wrote {folder.relative_to(ROOT)} ({len(charts) + 1} charts)")
    return 0


# ---------- shared pieces ----------


def _title(figure, theme, title: str, subtitle: str = "", y: float = 1.0) -> None:
    """Title and subtitle at fixed inches above `y`, clear of a legend row."""
    inch = 1 / figure.get_figheight()
    figure.text(0.0, y + 0.72 * inch, title, fontsize=15, fontweight="semibold", color=theme["ink"], ha="left", va="bottom")
    if subtitle:
        figure.text(0.0, y + 0.44 * inch, subtitle, fontsize=10, color=theme["ink2"], ha="left", va="bottom")


def _quiet(axis, theme, *, grid_axis: str | None = "x") -> None:
    for side in ("top", "right", "left"):
        axis.spines[side].set_visible(False)
    axis.spines["bottom"].set_color(theme["axis"])
    axis.spines["bottom"].set_linewidth(1)
    axis.tick_params(length=0, labelsize=9)
    if grid_axis:
        axis.grid(axis=grid_axis, color=theme["grid"], linewidth=1, linestyle="-")
        axis.set_axisbelow(True)


def _legend(axis, theme, items: list[tuple[str, str]], *, loc="lower left", anchor=(0.0, 1.0), ncol=None) -> None:
    handles = [Rectangle((0, 0), 1, 1, color=color) for _, color in items]
    legend = axis.legend(
        handles,
        [label for label, _ in items],
        loc=loc,
        bbox_to_anchor=anchor,
        ncol=ncol or len(items),
        frameon=False,
        fontsize=9,
        handlelength=1.0,
        handleheight=1.0,
        borderaxespad=0.2,
        columnspacing=1.4,
    )
    for text in legend.get_texts():
        text.set_color(theme["ink2"])


def _tint(color: str, theme, share: float = 0.32):
    """An opaque wash of `color` over the surface, so gridlines never show through."""
    top = matplotlib.colors.to_rgb(color)
    base = matplotlib.colors.to_rgb(theme["surface"])
    return tuple(share * a + (1 - share) * b for a, b in zip(top, base))


def _systems(result: dict) -> list[str]:
    return list(result["systems"])


# ---------- 01 ----------


def recall_by_bucket(theme, *, result, gold, **_):
    affected = {bucket: [row for row in gold if row["bucket"] == bucket and row["label"] == "affected"] for bucket in BUCKETS}
    buckets = [bucket for bucket in BUCKETS if affected[bucket]]
    by_id = {row["id"]: row for row in result["per_pair"]}

    def found(system: str, bucket: str) -> int:
        return sum(by_id[row["id"]]["said"][system] == "affected" for row in affected[bucket])

    figure, axis = plt.subplots(figsize=(8.2, 3.6))
    _title(figure, theme, "A legacy NVD pipeline misses 15 of 26 real vulnerabilities", "Affected gold pairs found, by bucket. B2, B3 and B4 find the same 26 as Sibyl.")
    height = 0.32
    for index, bucket in enumerate(buckets):
        total = len(affected[bucket])
        for offset, system, color in ((-height / 2 - 0.02, "Sibyl", theme["accent"]), (height / 2 + 0.02, "B1 NVD-CPE-only", theme["other"])):
            value = found(system, bucket)
            axis.barh(index + offset, total, height=height, color=theme["grid"], linewidth=0)
            axis.barh(index + offset, value, height=height, color=color, linewidth=0)
            axis.text(total + 0.25, index + offset, f"{value} of {total}", va="center", fontsize=9, color=theme["ink"] if system == "Sibyl" else theme["ink2"])
    axis.set_yticks(range(len(buckets)), [BUCKET_NAMES[bucket] for bucket in buckets], fontsize=10)
    axis.invert_yaxis()
    axis.set_xlim(0, 13)
    axis.set_xticks([])
    _quiet(axis, theme, grid_axis=None)
    axis.spines["bottom"].set_visible(False)
    _legend(axis, theme, [("Sibyl", theme["accent"]), ("B1 NVD-CPE-only", theme["other"]), ("Affected pairs in bucket", theme["grid"])])
    return figure


# ---------- 02 ----------


def gold_set(theme, *, gold, **_):
    figure = plt.figure(figsize=(9.6, 3.9))
    _title(figure, theme, "40 gold pairs, each labelled from the upstream fix commit", "Picked from source positions only, frozen before tuning, reviewed by a human. 26 affected, 18 hard.")
    axis = figure.add_axes([0.0, 0.02, 0.52, 0.74])
    axis.set_axis_off()
    colors = dict(zip(BUCKETS, theme["series"]))
    column = 0
    rows = 4
    for bucket in BUCKETS:
        members = [row for row in gold if row["bucket"] == bucket]
        start = column
        for index, row in enumerate(members):
            x = column + index // rows
            y = rows - 1 - index % rows
            face = colors[bucket] if row["label"] == "affected" else "none"
            axis.add_patch(FancyBboxPatch((x + 0.06, y + 0.06), 0.88, 0.88, boxstyle="round,pad=0,rounding_size=0.12", facecolor=face, edgecolor=colors[bucket], linewidth=2))
        width = -(-len(members) // rows)
        axis.text(start + width / 2, -0.35, f"{STACKED.get(bucket, BUCKET_NAMES[bucket]) if width == 1 else BUCKET_NAMES[bucket]}\n{len(members)}", ha="center", va="top", fontsize=8.5, color=theme["ink2"])
        column += width + 1.0
    axis.set_xlim(-0.1, column)
    axis.set_ylim(-2.3, rows + 0.1)
    axis.set_aspect("equal")
    axis.text(0, rows + 0.35, "■ affected    □ not affected", fontsize=8.5, color=theme["ink2"], va="bottom")
    card = figure.add_axes([0.56, 0.06, 0.44, 0.78])
    card.set_axis_off()
    card.add_patch(FancyBboxPatch((0, 0), 1, 1, boxstyle="round,pad=0,rounding_size=0.04", facecolor=theme["card"], edgecolor="none", transform=card.transAxes))
    lines = [
        ("Example label · G027", 11, "semibold", theme["ink"]),
        ("validator@13.7.0 × CVE-2025-56200", 10, "normal", theme["ink"]),
        ("NVD CPE says ≤ 3.15.15  (a typo)", 9.5, "normal", theme["ink2"]),
        ("NVD text says through 13.15.15", 9.5, "normal", theme["ink2"]),
        ("Fix cbef508 first ships in 13.15.20", 9.5, "normal", theme["ink2"]),
        ("13.7.0 lacks the fix  →  affected", 10, "semibold", theme["ink"]),
    ]
    y = 0.86
    for text, size, weight, color in lines:
        card.text(0.07, y, text, fontsize=size, fontweight=weight, color=color, transform=card.transAxes, va="top")
        y -= 0.14 if size >= 10 else 0.125
    return figure


# ---------- 03 ----------


def stat_panel(theme, *, result, **_):
    systems = result["systems"]
    runtime = result["runtime"]
    sibyl = systems["Sibyl"]
    tiles = [
        (f"{sibyl['precision'] * 100:.1f}%", "Precision", f"at 100% recall\n(B2–B3: {systems['B2 OSV-only']['precision'] * 100:.1f}%)"),
        (f"{runtime['Sibyl']['tokens_per_case']:.0f}", "Tokens per case", f"B4 returned {result['gold']['pairs'] - systems['B4 single-pass LLM'].get('not_reported', 0)}/{result['gold']['pairs']} answers;\nno token-ratio claim"),
        (f"{sibyl['cases_with_provenance']} / {sibyl['cases']}", "Verdicts with a source", "every verdict cites the\nadvisory record it came from"),
        (f"{systems['Sibyl run 2']['accuracy'] * 100:.1f}%", "Accuracy after one answer", f"full retriage with memory\n(run 1: {sibyl['accuracy'] * 100:.1f}%)"),
    ]
    figure = plt.figure(figsize=(11, 2.9))
    _title(figure, theme, "Reconciliation quality, cost and provenance", "Full set, scored on the 40 reviewed gold pairs.", y=0.98)
    for index, (value, label, note) in enumerate(tiles):
        axis = figure.add_axes([index * 0.25 + 0.005, 0.0, 0.235, 0.92])
        axis.set_axis_off()
        axis.add_patch(FancyBboxPatch((0, 0), 1, 1, boxstyle="round,pad=0,rounding_size=0.05", facecolor=theme["card"], edgecolor="none", transform=axis.transAxes))
        axis.text(0.08, 0.84, label, fontsize=10.5, color=theme["ink2"], transform=axis.transAxes, va="top")
        axis.text(0.08, 0.64, value, fontsize=30, fontweight="semibold", color=theme["ink"], transform=axis.transAxes, va="top")
        axis.text(0.08, 0.27, note, fontsize=8.8, color=theme["muted"], transform=axis.transAxes, va="top", linespacing=1.35)
    return figure


# ---------- 04 ----------


def per_pair_grid(theme, *, result, **_):
    systems = _systems(result)
    rows = result["per_pair"]
    order = sorted(rows, key=lambda row: (BUCKETS.index(row["bucket"]), row["id"]))
    gap = 1.2
    positions = []
    y = 0.0
    last = None
    for row in order:
        if last is not None and row["bucket"] != last:
            y += gap
        positions.append(y)
        last = row["bucket"]
        y += 1
    figure, axis = plt.subplots(figsize=(10.5, 13.2))
    figure.subplots_adjust(top=0.95, bottom=0.04)
    _title(figure, theme, "Verdicts, escalations and missing responses", "Each row is a gold pair. Run 2 remembers the human answer; fresh judgements can vary.", y=0.95)
    glyph = {"good": "✓", "warning": "?", "critical": "✗"}
    for row, top in zip(order, positions):
        for column, system in enumerate(systems):
            said = row["said"].get(system, "not_affected")
            if said == "missing":
                axis.add_patch(Rectangle((column + 0.04, top + 0.06), 0.92, 0.88, facecolor=theme['other'], edgecolor='none'))
                axis.text(column + 0.5, top + 0.5, '—', ha='center', va='center', fontsize=9, color=theme['ink'])
                continue
            state = "warning" if said == "uncertain" else "good" if said == row["label"] else "critical"
            axis.add_patch(Rectangle((column + 0.04, top + 0.06), 0.92, 0.88, facecolor=_tint(STATUS[state], theme) if state == "good" else STATUS[state], edgecolor="none"))
            axis.text(column + 0.5, top + 0.5, glyph[state], ha="center", va="center", fontsize=9, color=theme["ink"] if state == "good" else "#ffffff", fontweight="bold")
        mark = "  ← braces: withdrawn advisory" if "braces" in row["pair"] else "  ← NVD's narrower range was right" if "aiohttp" in row["pair"] else ""
        axis.text(-0.15, top + 0.5, row["pair"], ha="right", va="center", fontsize=8, color=theme["ink2"])
        if mark:
            axis.text(len(systems) + 0.1, top + 0.5, mark, ha="left", va="center", fontsize=8.5, color=theme["ink"])
    starts = {}
    for row, top in zip(order, positions):
        starts.setdefault(row["bucket"], top)
    for bucket, top in starts.items():
        axis.text(-0.15, top - 0.12, BUCKET_NAMES[bucket].upper(), ha="right", va="bottom", fontsize=7.5, color=theme["muted"], fontweight="semibold")
    for column, system in enumerate(systems):
        axis.text(column + 0.5, -0.6, SHORT[system], ha="center", va="bottom", rotation=0, fontsize=8.5, color=theme["ink"] if system.startswith("Sibyl") else theme["ink2"], fontweight="semibold" if system == "Sibyl" else "normal", wrap=True)
    axis.set_xlim(-0.1, len(systems) + 0.1)
    axis.set_ylim(positions[-1] + 1.1, -1.4)
    axis.set_axis_off()
    axis.legend(
        [Rectangle((0, 0), 1, 1, color=_tint(STATUS["good"], theme)), Rectangle((0, 0), 1, 1, color=STATUS["warning"]), Rectangle((0, 0), 1, 1, color=STATUS["critical"]), Rectangle((0, 0), 1, 1, color=theme['other'])],
        ["✓ correct", "? escalated to a human", "✗ wrong", "— not reported"],
        loc="upper left",
        bbox_to_anchor=(0.0, 0.0),
        ncol=2,
        frameon=False,
        fontsize=9,
        labelcolor=theme["ink2"],
    )
    return figure


# ---------- 05 ----------


def cost_per_case(theme, *, result, **_):
    runtime = result["runtime"]
    incomplete = result['systems']['B4 single-pass LLM'].get('not_reported', 0)
    names = ["Sibyl", "Sibyl − critic"] if incomplete else ["B4 single-pass LLM", "Sibyl", "Sibyl − critic"]
    figure, (left, right) = plt.subplots(1, 2, figsize=(10.5, 2.9), gridspec_kw={"wspace": 0.55})
    _title(figure, theme, "Measured cost of completed runs", f"B4 has {incomplete} missing responses; no efficiency ratio against that incomplete baseline." if incomplete else "Token and runtime measurements for this collection.", y=0.97)
    seconds = {name: runtime[name]["wall_seconds"] / runtime[name]["cases"] for name in names}
    for axis, values, label, fmt in (
        (left, {name: runtime[name]["tokens_per_case"] for name in names}, "Tokens per case (log scale)", "{:,.0f}"),
        (right, seconds, "Seconds per case (log scale)", "{:.2f} s"),
    ):
        for index, name in enumerate(names):
            color = theme["accent"] if name == "Sibyl" else theme["other"]
            axis.barh(index, values[name], height=0.5, color=color, linewidth=0)
            axis.text(values[name] * 1.15, index, fmt.format(values[name]), va="center", fontsize=9.5, color=theme["ink"])
        axis.set_xscale("log")
        axis.set_yticks(range(len(names)), [SHORT[name] for name in names], fontsize=9.5)
        axis.invert_yaxis()
        axis.set_xlim(min(values.values()) / 3, max(values.values()) * 6)
        axis.set_title(label, loc="left", fontsize=9.5, color=theme["ink2"], pad=8)
        _quiet(axis, theme)
        axis.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _p: f"{v:,.0f}" if v >= 1 else f"{v:g}"))
    figure.text(0.0, -0.06, f"B4: {runtime['B4 single-pass LLM']['cases'] - incomplete}/{runtime['B4 single-pass LLM']['cases']} answers. Sibyl: all {runtime['Sibyl']['cases']} cases of the full set.", fontsize=8.5, color=theme["muted"])
    return figure


# ---------- 06 ----------


def outcome_stack(theme, *, result, **_):
    systems = [name for name in _systems(result) if name != "B1 NVD-CPE-only"] + ["B1 NVD-CPE-only"]
    figure, axis = plt.subplots(figsize=(9.2, 3.8))
    missing = result['systems']['B4 single-pass LLM'].get('not_reported', 0)
    _title(figure, theme, "Correct, escalated and wrong under the scoring rule", f"Out of 40 gold pairs. B4 has {missing} missing responses, scored as not affected.")
    for index, name in enumerate(systems):
        scored = result["systems"][name]
        correct = scored["correct"]
        unsure = scored["uncertain"]
        wrong = 40 - correct - unsure
        left = 0
        for value, state in ((correct, "good"), (unsure, "warning"), (wrong, "critical")):
            if value:
                axis.barh(index, value - 0.25, left=left, height=0.55, color=_tint(STATUS[state], theme) if state == "good" else STATUS[state], linewidth=0)
                if value >= 2:
                    axis.text(left + (value - 0.25) / 2, index, str(value), ha="center", va="center", fontsize=9, color=theme["ink"] if state == "good" else "#ffffff", fontweight="semibold")
                left += value
    axis.set_yticks(range(len(systems)), [SHORT[name] for name in systems], fontsize=9.5)
    for label in axis.get_yticklabels():
        if label.get_text().startswith("Sibyl"):
            label.set_color(theme["ink"])
            label.set_fontweight("semibold")
    axis.invert_yaxis()
    axis.set_xlim(0, 40)
    axis.set_xticks([0, 10, 20, 30, 40])
    _quiet(axis, theme)
    _legend(
        axis,
        theme,
        [("Correct", _tint(STATUS["good"], theme)), ("Escalated to a human", STATUS["warning"]), ("Wrong", STATUS["critical"])],
    )
    return figure


# ---------- 07 ----------


def case_annotated(theme):
    image = plt.imread(CASE_PNG)
    height, width = image.shape[:2]
    fig_w, fig_h = width / 150 + 5.2, height / 150 + 1.5
    figure = plt.figure(figsize=(fig_w, fig_h))
    figure.patch.set_facecolor(theme["surface"])
    axis = figure.add_axes([0.0, 0.55 / fig_h, (width / 150) / fig_w, (height / 150) / fig_h])
    axis.imshow(image)
    axis.set_axis_off()
    figure.text(0.01, 0.985, "Every verdict shows its work: the validator case file", fontsize=17, fontweight="semibold", color=theme["ink"], va="top")
    notes = [
        (180, "The verdict: affected, decided by the critic, not by one feed."),
        (572, "Provenance: NVD and OSV both give a range. NVD's CPE bound is a typo (≤ 3.15.15)."),
        (856, "Critic: the CPE bound contradicts a version in NVD's own description. Send back."),
        (1012, "Matcher re-reads the description and quotes it: \"through version 13.15.15\"."),
    ]
    x_note = 1.02
    for number, (y, text) in enumerate(notes, start=1):
        axis.add_patch(plt.Circle((1500, y), 22, color=theme["accent"]))
        axis.text(1500, y, str(number), ha="center", va="center", fontsize=11, color="#ffffff", fontweight="bold")
        axis.annotate(
            f"{number}  {text}",
            xy=(1525, y),
            xytext=(x_note, 1 - y / height),
            textcoords="axes fraction",
            fontsize=11,
            color=theme["ink"],
            va="center",
            wrap=True,
            arrowprops={"arrowstyle": "-", "color": theme["muted"], "linewidth": 1},
        )
    figure.text(
        0.01,
        0.15 / fig_h,
        "Then the conflict clears and the verdict stays affected, linked to fix commit cbef508. Gold label G027: affected.",
        fontsize=11,
        color=theme["ink2"],
    )
    return figure


# ---------- 08 ----------


def memory_effect(theme, *, result, **_):
    memory = result["memory_effect"]
    metrics = [
        ("Escalations", memory["escalations"], "{:,.0f}"),
        ("Needs human", memory["needs_human"], "{:,.0f}"),
        ("LLM calls", memory["llm_calls"], "{:,.0f}"),
        ("Tokens", memory["tokens"], "{:,.0f}"),
        ("Wall seconds", memory["wall_seconds"], "{:,.0f}"),
    ]
    figure, axis = plt.subplots(figsize=(8.6, 3.6))
    resolved = memory["resolved_in_run1"]
    _title(
        figure,
        theme,
        "An answer is remembered; fresh judgement still varies",
        f"Full retriage after {resolved} human resolution, as a share of run 1. Gold accuracy {result['systems']['Sibyl']['accuracy'] * 100:.1f}% → {result['systems']['Sibyl run 2']['accuracy'] * 100:.1f}%.",
    )
    for index, (label, (first, second), fmt) in enumerate(metrics):
        share = second / first * 100
        axis.plot([share, 100], [index, index], color=theme["axis"], linewidth=2, solid_capstyle="round", zorder=1)
        axis.scatter([100], [index], s=70, color=theme["other"], edgecolor=theme["surface"], linewidth=2, zorder=2)
        axis.scatter([share], [index], s=70, color=theme["accent"], edgecolor=theme["surface"], linewidth=2, zorder=3)
        axis.annotate(fmt.format(first), (100, index), xytext=(0, -9), textcoords='offset points', va='top', ha='center', fontsize=9, color=theme['ink2'])
        axis.annotate(f"{fmt.format(second)}  ({share - 100:+.0f}%)", (share, index), xytext=(0, 9), textcoords='offset points', va='bottom', ha='center', fontsize=9, color=theme['ink'])
    axis.set_yticks(range(len(metrics)), [label for label, _, _ in metrics], fontsize=9.5)
    axis.invert_yaxis()
    axis.set_ylim(len(metrics) - 0.55, -0.45)
    shares = [second / first * 100 for _, (first, second), _ in metrics]
    lower = min(68, min(shares) - 24)
    upper = max(107, max(shares) + 16)
    axis.set_xlim(lower, upper)
    ticks = list(range(int(lower // 10 + 1) * 10, int(upper // 10) * 10 + 1, 10))
    axis.set_xticks(ticks, [f"{value}%" for value in ticks])
    _quiet(axis, theme)
    _legend(axis, theme, [("Run 1", theme["other"]), ("Run 2", theme["accent"])])
    return figure


# ---------- 09 ----------


def join_gap(theme, **_):
    figure, axis = plt.subplots(figsize=(10.8, 3.7))
    _title(figure, theme, "One data gap explains Sibyl's two wrong answers", "NVD's correct aiohttp range never reaches Sibyl, so there is no conflict to see.", y=0.97)
    axis.set_axis_off()
    axis.set_xlim(0, 10.8)
    axis.set_ylim(0.25, 3.9)

    def box(x, y, w, text, *, tone="card", ink=None, size=9.5):
        face = theme["card"] if tone == "card" else matplotlib.colors.to_rgba(STATUS[tone], 0.18)
        axis.add_patch(FancyBboxPatch((x, y), w, 0.78, boxstyle="round,pad=0,rounding_size=0.1", facecolor=face, edgecolor="none"))
        axis.text(x + w / 2, y + 0.39, text, ha="center", va="center", fontsize=size, color=ink or theme["ink"], linespacing=1.3)

    def arrow(x1, x2, y):
        axis.annotate("", xy=(x2, y), xytext=(x1, y), arrowprops={"arrowstyle": "-|>", "color": theme["muted"], "linewidth": 1.2})

    rows = [
        (2.95, "validator (npm)", "cpe:…:validator:…:node.js:*:*", "ecosystem = npm", "joins npm", "good", "conflict seen → sent back"),
        (1.85, "aiohttp (PyPI)", "cpe:…:aiohttp:aiohttp:…:*:*:*", "ecosystem = nvd", "no join to pypi", "critical", "only OSV + GHSA → affected"),
    ]
    for y, label, cpe, eco, join, tone, outcome in rows:
        axis.text(0.0, y + 0.39, label, fontsize=10, fontweight="semibold", va="center", color=theme["ink"])
        box(1.6, y, 2.55, cpe, size=8.5)
        arrow(4.2, 4.45, y + 0.39)
        box(4.5, y, 1.45, eco, size=9)
        arrow(6.0, 6.25, y + 0.39)
        box(6.3, y, 1.65, ("✓ " if tone == "good" else "✗ ") + join, tone=tone, size=9)
        arrow(8.0, 8.25, y + 0.39)
        box(8.3, y, 2.5, outcome, size=8.8)
    axis.text(1.6, 1.3, "The CPE's target-software field (second to last) names the platform. Blank (*) files the row under 'nvd'.", fontsize=8.8, color=theme["ink2"])
    axis.text(0.0, 0.5, "Same cause:", fontsize=10, fontweight="semibold", color=theme["ink"])
    axis.text(1.3, 0.5, "both false positives  ·  all 3 missed conflicts  ·  wrong-confident 5.7%. B1 joins on the name alone, so it saw NVD.", fontsize=9.3, color=theme["ink2"])
    return figure


# ---------- 10 ----------


def critic_conflicts(theme, *, result, **_):
    effect = result["critic_effect"]
    figure, axis = plt.subplots(figsize=(7.6, 2.5))
    _title(
        figure,
        theme,
        "The critic surfaces conflicts; here it does not change the verdicts",
        f"Gold conflicts surfaced (range conflicts and withdrawn records). {effect['sendbacks']} send-backs, {effect['sendbacks_that_changed_verdict']} changed a verdict.",
    )
    rows = [("Sibyl", theme["accent"]), ("Sibyl − critic", theme["other"])]
    for index, (name, color) in enumerate(rows):
        scored = result["systems"][name]
        axis.barh(index, scored["conflicts_in_gold"], height=0.45, color=theme["grid"], linewidth=0)
        axis.barh(index, scored["conflicts_surfaced"], height=0.45, color=color, linewidth=0)
        axis.text(scored["conflicts_in_gold"] + 0.15, index, f"{scored['conflicts_surfaced']} of {scored['conflicts_in_gold']}  ({scored['conflict_detection'] * 100:.0f}%)", va="center", fontsize=9.5, color=theme["ink"])
    axis.set_yticks(range(len(rows)), [SHORT[name] for name, _ in rows], fontsize=9.5)
    axis.invert_yaxis()
    axis.set_xlim(0, 12)
    axis.set_xticks([])
    _quiet(axis, theme, grid_axis=None)
    axis.spines["bottom"].set_visible(False)
    return figure


# ---------- 11 ----------


def outage_matrix(theme, *, robust, **_):
    rows = [row for row in robust["outages"] if row["disabled"] != "none"]
    base = next(row for row in robust["outages"] if row["disabled"] == "none")
    effects = {
        "osv": f"confidence lower on {next(r for r in rows if r['disabled'] == 'osv')['confidence_lowered']} cases",
        "ghsa": "GHSA-only cases drop out",
        "cve_org": f"text-only cases {base['text_cases']} → {next(r for r in rows if r['disabled'] == 'cve_org')['text_cases']}",
        "nvd": "no NVD positions",
        "kev": "no case marked exploited",
        "epss": "no EPSS score component",
        "euvd": "aliases only; verdicts unchanged",
    }
    names = {"osv": "OSV", "ghsa": "GHSA", "cve_org": "CVE.org", "nvd": "NVD", "kev": "CISA KEV", "epss": "FIRST EPSS", "euvd": "ENISA EUVD"}
    order = ["osv", "ghsa", "nvd", "cve_org", "kev", "epss", "euvd"]
    columns = ["Run\nfinished", "Marked\ndegraded", "Receipt says\n'disabled'", "Expected\neffect seen"]
    figure, axis = plt.subplots(figsize=(10.2, 3.9))
    _title(figure, theme, "Take any one source away, and the run still finishes", "Fixture runs with one source in DISABLE_SOURCES each. Every check passed.", y=0.97)
    for r, source in enumerate(order):
        row = next(item for item in rows if item["disabled"] == source)
        checks = [row["state"] == "DONE" and not row["partial"], row["degraded"], row["ingest_receipt"] == "disabled", row.get("passed", False)]
        axis.text(-0.1, r + 0.5, names[source], ha="right", va="center", fontsize=10, color=theme["ink"])
        for c, ok in enumerate(checks):
            state = "good" if ok else "critical"
            axis.add_patch(FancyBboxPatch((c + 0.08, r + 0.12), 0.84, 0.76, boxstyle="round,pad=0,rounding_size=0.08", facecolor=_tint(STATUS[state], theme) if ok else STATUS[state], edgecolor="none"))
            axis.text(c + 0.5, r + 0.5, "✓" if ok else "✗", ha="center", va="center", fontsize=11, fontweight="bold", color=theme["ink"])
        axis.text(len(columns) + 0.15, r + 0.5, effects[source], va="center", fontsize=9.5, color=theme["ink2"])
    for c, label in enumerate(columns):
        axis.text(c + 0.5, -0.25, label, ha="center", va="bottom", fontsize=8.8, color=theme["ink2"])
    axis.text(len(columns) + 0.15, -0.25, "What changed", ha="left", va="bottom", fontsize=8.8, color=theme["ink2"])
    axis.set_xlim(-1.4, len(columns) + 3.6)
    axis.set_ylim(len(order) + 0.1, -0.9)
    axis.set_axis_off()
    return figure


# ---------- 12 ----------


def osv_down(theme, *, robust, **_):
    base = next(row for row in robust["outages"] if row["disabled"] == "none")
    osv = next(row for row in robust["outages"] if row["disabled"] == "osv")
    figure, (left, right) = plt.subplots(1, 2, figsize=(9.4, 2.7), gridspec_kw={"wspace": 0.45})
    _title(figure, theme, "When the best source goes down, Sibyl gets careful, not wrong", "Fixture run, normal vs OSV disabled. Lower trust means more questions for a human.", y=0.97)
    panels = (
        (left, "Cases sent to a human", base["needs_human"], osv["needs_human"]),
        (right, "Cases with lower confidence", 0, osv["confidence_lowered"]),
    )
    for axis, label, normal, down in panels:
        for index, (name, value, color) in enumerate((("Normal", normal, theme["other"]), ("OSV down", down, theme["accent"]))):
            axis.barh(index, max(value, 0.001), height=0.5, color=color, linewidth=0)
            axis.text(value + max(normal, down) * 0.03, index, str(value), va="center", fontsize=10, color=theme["ink"])
        axis.set_yticks([0, 1], ["Normal", "OSV down"], fontsize=9.5)
        axis.invert_yaxis()
        axis.set_xlim(0, max(normal, down) * 1.25)
        axis.set_title(label, loc="left", fontsize=9.5, color=theme["ink2"], pad=8)
        _quiet(axis, theme)
    return figure


# ---------- 13 ----------


def defences(theme, *, robust, **_):
    idem = robust["idempotency"]
    records = 0
    for text in idem["reingest"].values():
        records += int(text.rsplit(",", 1)[1].split()[0])
    figure = plt.figure(figsize=(11, 3.4))
    _title(figure, theme, "Built to fail safe", "Three failure modes, each with a test.", y=0.98)
    cards = [
        (
            "Rate limits and outages",
            ["429 / 503 / timeout", "→ retry  → retry", "→ last snapshot, marked degraded"],
            "Unit test for all 7 sources",
        ),
        (
            "Prompt injection",
            ["\"Ignore previous instructions…\"", "→ injection filter", "→ quarantined; the rows decide"],
            "Never reaches the model",
        ),
        (
            "Idempotency",
            [f"Re-ingest {records:,} records", "→ 0 new, 0 changed", "→ World Model diff empty"],
            "Same input, same state",
        ),
    ]
    for index, (title, lines, foot) in enumerate(cards):
        axis = figure.add_axes([index * 0.335, 0.0, 0.315, 0.9])
        axis.set_axis_off()
        axis.add_patch(FancyBboxPatch((0, 0), 1, 1, boxstyle="round,pad=0,rounding_size=0.05", facecolor=theme["card"], edgecolor="none", transform=axis.transAxes))
        axis.text(0.07, 0.86, title, fontsize=12, fontweight="semibold", color=theme["ink"], transform=axis.transAxes, va="top")
        y = 0.66
        for line in lines:
            axis.text(0.07, y, line, fontsize=10, color=theme["ink2"], transform=axis.transAxes, va="top")
            y -= 0.15
        axis.text(0.07, 0.12, "✓ " + foot, fontsize=9.5, color=STATUS["good"], transform=axis.transAxes, va="bottom", fontweight="semibold")
    return figure


if __name__ == "__main__":
    raise SystemExit(main())
