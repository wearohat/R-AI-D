import io
from dataclasses import dataclass, field
from typing import Any, Optional, Sequence

from matplotlib.figure import Figure
from matplotlib.ticker import MaxNLocator

from gui import data as d

SURFACE = "#1a1f2b"
TEXT_SECONDARY = "#c3c2b7"
TEXT_MUTED = "#898781"
GRID = "#2a3040"
AXIS = "#3a4258"
SERIES = "#3987e5"
ACCENT = "#d95926"

FIGSIZE = (6.4, 3.6)
BAR_THICKNESS = 0.56
MIN_ROW_SLOTS = 5


@dataclass
class HoverTarget:
    artists: Sequence[Any]
    texts: Sequence[str]


@dataclass
class Chart:
    key: str
    title: str
    subtitle: str
    figure: Figure
    columns: list
    rows: list
    hover: list = field(default_factory=list)
    empty: bool = False


def _figure(figsize=FIGSIZE):
    fig = Figure(figsize=figsize, dpi=100, facecolor=SURFACE, layout="constrained")
    ax = fig.add_subplot(1, 1, 1)
    ax.set_facecolor(SURFACE)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(AXIS)
    ax.tick_params(colors=TEXT_MUTED, labelcolor=TEXT_SECONDARY, labelsize=8.5, length=0)
    ax.set_axisbelow(True)
    return fig, ax


def _empty(chart, ax, message):
    ax.set_xticks([])
    ax.set_yticks([])
    ax.spines["bottom"].set_visible(False)
    ax.text(0.5, 0.5, message, transform=ax.transAxes, ha="center", va="center", color=TEXT_MUTED, fontsize=10)
    chart.empty = True
    return chart


def _fmt(value):
    return f"{value:.1f}" if isinstance(value, float) and not value.is_integer() else f"{int(value)}"


def _short(label, width=34):
    return label if len(label) <= width else label[: width - 1] + "…"


def _labels(ax, bars, values, horizontal):
    for bar, value in zip(bars, values):
        if not value:
            continue
        if horizontal:
            ax.annotate(_fmt(value), (bar.get_width(), bar.get_y() + bar.get_height() / 2), xytext=(4, 0),
                        textcoords="offset points", va="center", fontsize=8, color=TEXT_SECONDARY)
        else:
            ax.annotate(_fmt(value), (bar.get_x() + bar.get_width() / 2, bar.get_height()), xytext=(0, 3),
                        textcoords="offset points", ha="center", fontsize=8, color=TEXT_SECONDARY)


def ranked_bars(key, title, subtitle, items, columns, unit, empty_message, xmax=None, colors=None, label_width=34):
    items = list(items)
    fig, ax = _figure((FIGSIZE[0], max(FIGSIZE[1], 0.32 * len(items) + 1.0)))
    chart = Chart(key, title, subtitle, fig, columns, [[label, value] for label, value in items])
    if not items:
        return _empty(chart, ax, empty_message)
    values = [value for _, value in items]
    bars = ax.barh(range(len(items)), values, BAR_THICKNESS, color=colors or SERIES, edgecolor=SURFACE, linewidth=1.5)
    _labels(ax, bars, values, horizontal=True)
    chart.hover.append(HoverTarget(bars.patches, [f"{label}\n{_fmt(value)} {unit}" for label, value in items]))
    ax.set_yticks(range(len(items)), [_short(label, label_width) for label, _ in items])
    ax.set_ylim(max(len(items), MIN_ROW_SLOTS) - 0.5, -0.5)
    if xmax is not None:
        ax.set_xlim(0, xmax * 1.08)
        ax.set_xticks(range(0, int(xmax) + 1, 2))
    else:
        ax.xaxis.set_major_locator(MaxNLocator(integer=True))
        ax.margins(x=0.12)
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    return chart


def top_scores_chart(scan):
    rows = d.top_results(scan)
    items = [(r["subdomain"], d.score_of(r)) for r in rows]
    model = next((f"{r.get('provider')}:{r.get('model')}" for r in rows if r.get("model")), None)
    subtitle = "AI score per subdomain (0–10)" + (f" · {model}" if model else "")
    chart = ranked_bars("top", "Highest-scoring subdomains", subtitle, items, ["Subdomain", "Score"], "/ 10",
                        "No AI results yet", xmax=10)
    if items:
        chart.rows = [[r["subdomain"], d.score_of(r), len(r.get("suggestions") or [])] for r in rows]
        chart.columns = ["Subdomain", "Score", "Suggestions"]
    return chart


def score_distribution_chart(scan):
    counts = d.score_distribution(scan)
    fig, ax = _figure()
    chart = Chart("scores", "Score distribution", "Number of subdomains per AI score",
                  fig, ["Score", "Subdomains"], [[s, n] for s, n in counts])
    if not any(n for _, n in counts):
        return _empty(chart, ax, "No AI results yet")
    values = [n for _, n in counts]
    bars = ax.bar([s for s, _ in counts], values, BAR_THICKNESS, color=SERIES, edgecolor=SURFACE, linewidth=1.5)
    _labels(ax, bars, values, horizontal=False)
    chart.hover.append(HoverTarget(bars.patches, [f"Score {s}: {n} subdomain{'s' if n != 1 else ''}" for s, n in counts]))
    ax.set_xticks(range(0, 11))
    ax.set_xlabel("AI score", color=TEXT_MUTED, fontsize=8.5)
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.margins(y=0.15)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    return chart


def ports_chart(scan):
    return ranked_bars("ports", "Exposed ports", "Hosts reporting each open port (InternetDB)",
                       d.port_exposure(scan), ["Port", "Hosts"], "host(s)", "No InternetDB data yet")


def vulns_chart(scan):
    return ranked_bars("vulns", "Known vulnerabilities", "CVE references per subdomain (InternetDB)",
                       d.vulnerable_subdomains(scan), ["Subdomain", "CVEs"], "CVE(s)",
                       "No CVEs reported for this target", colors=ACCENT)


def technologies_chart(scan):
    return ranked_bars("tech", "Technologies", "Hosts per detected product (InternetDB CPEs)",
                       d.technologies(scan), ["Technology", "Hosts"], "host(s)", "No technologies detected")


def virustotal_chart(scan):
    return ranked_bars("virustotal", "VirusTotal detections",
                       "Vendors flagging each subdomain as malicious or suspicious (70+ engines)",
                       d.virustotal_flagged(scan), ["Subdomain", "Vendors"], "vendor(s)",
                       "No VirusTotal detections (or no API key set)", colors=ACCENT)


def urlhaus_chart(scan):
    return ranked_bars("urlhaus", "URLhaus malware URLs",
                       "Known malware-distribution URLs per subdomain (community reports)",
                       d.urlhaus_listed(scan), ["Subdomain", "URLs"], "URL(s)",
                       "No URLhaus listings (or no API key set)", colors=ACCENT)


def mitre_chart(scan):
    rows = d.mitre_rows(scan)
    chart = ranked_bars("mitre", "MITRE ATT&CK techniques",
                        "Records collected per reconnaissance technique (tactic TA0043)",
                        rows, ["Technique", "Records"], "record(s)", "Run a scan to see the techniques used",
                        label_width=70)
    chart.figure.set_size_inches(12.8, max(FIGSIZE[1], 0.32 * len(rows) + 1.0))
    return chart


def coverage_chart(scan):
    summary = scan.summary
    subtitle = "How far each subdomain got through the pipeline"
    if summary.get("domain"):
        subtitle += f" · {summary['domain']}"
    rows = d.coverage(scan)
    if not rows[0][1]:
        rows = []
    return ranked_bars("coverage", "Pipeline coverage", subtitle, rows, ["Stage", "Subdomains"], "subdomain(s)",
                       "Run a scan to see coverage")


def build_charts(scan):
    return [
        top_scores_chart(scan),
        score_distribution_chart(scan),
        coverage_chart(scan),
        ports_chart(scan),
        vulns_chart(scan),
        technologies_chart(scan),
        virustotal_chart(scan),
        urlhaus_chart(scan),
        mitre_chart(scan),
    ]


def chart_tooltip(chart: Chart, event) -> Optional[str]:
    for target in chart.hover:
        for artist, text in zip(target.artists, target.texts):
            if artist.contains(event)[0]:
                return text
    return None


def figure_to_png(figure, dpi=100):
    buffer = io.BytesIO()
    figure.savefig(buffer, format="png", dpi=dpi, facecolor=figure.get_facecolor())
    return buffer.getvalue()
