"""Chart generator factory.
Produces Matplotlib charts as base64-encoded PNG strings (embedded in HTML).
All charts use chart_styles.py for consistent visual appearance.
"""
import io
import base64
from typing import Optional

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
from matplotlib.patches import Patch

from reporting.charts.chart_styles import (
    apply_base_style, make_figure, make_figure_multi,
    PRIMARY, SECONDARY, DANGER, WARNING, SUCCESS,
    FWD_COLOR, REV_COLOR, SERIES_COLORS, GRID_COLOR, AXIS_LABEL, TITLE_COLOR
)


def _fig_to_b64(fig) -> str:
    """Convert a matplotlib figure to a base64 PNG string for HTML embedding."""
    buf = io.BytesIO()
    fig.savefig(buf, format='png', bbox_inches='tight', facecolor=fig.get_facecolor())
    buf.seek(0)
    encoded = base64.b64encode(buf.read()).decode('utf-8')
    plt.close(fig)
    return encoded


def bandwidth_chart(time_labels: list[str], fwd_bytes: list[float],
                    rev_bytes: list[float]) -> str:
    """
    Line chart: bytes sent (forward) and bytes received (reverse) over time.
    Returns base64 PNG.
    """
    fig, ax = make_figure(width_in=7.5, height_in=3.0)
    if time_labels and fwd_bytes:
        ax.plot(range(len(fwd_bytes)), fwd_bytes, color=FWD_COLOR, linewidth=1.5,
                label='Bytes Sent')
        ax.fill_between(range(len(fwd_bytes)), fwd_bytes, alpha=0.15, color=FWD_COLOR)
    if time_labels and rev_bytes:
        ax.plot(range(len(rev_bytes)), rev_bytes, color=REV_COLOR, linewidth=1.5,
                label='Bytes Received')
        ax.fill_between(range(len(rev_bytes)), rev_bytes, alpha=0.1, color=REV_COLOR)

    apply_base_style(ax, title='Bandwidth Over Time', ylabel='Bytes / interval')

    # X-axis ticks — show at most 8 labels
    if time_labels:
        step = max(1, len(time_labels) // 8)
        ax.set_xticks(range(0, len(time_labels), step))
        ax.set_xticklabels(time_labels[::step], rotation=30, ha='right', fontsize=7)

    ax.yaxis.set_major_formatter(mticker.FuncFormatter(
        lambda x, _: f'{x/1e6:.1f}MB' if x >= 1e6 else f'{x/1e3:.0f}KB'
    ))

    ax.legend(loc='upper right', fontsize=8, framealpha=0.8)
    fig.tight_layout(pad=1.0)
    return _fig_to_b64(fig)


def protocol_pie_chart(labels: list[str], counts: list[int]) -> str:
    """
    Pie chart: protocol distribution.
    Returns base64 PNG.
    """
    fig, ax = make_figure(width_in=5.0, height_in=4.0)
    if not labels or not counts or sum(counts) == 0:
        ax.text(0.5, 0.5, 'No data', ha='center', va='center', transform=ax.transAxes,
                color=AXIS_LABEL, fontsize=12)
        ax.set_axis_off()
    else:
        colors = SERIES_COLORS[:len(labels)]
        wedges, texts, autotexts = ax.pie(
            counts, labels=None, colors=colors, autopct='%1.1f%%',
            startangle=90, pctdistance=0.8,
            wedgeprops={'linewidth': 1, 'edgecolor': 'white'}
        )
        for t in autotexts:
            t.set_fontsize(8)
            t.set_color('white')
        ax.legend(
            wedges, labels, loc='lower center', bbox_to_anchor=(0.5, -0.12),
            ncol=3, fontsize=8, framealpha=0.9
        )
        ax.set_title('Protocol Distribution', color=TITLE_COLOR, fontsize=11, fontweight='bold')

    fig.tight_layout(pad=1.0)
    return _fig_to_b64(fig)


def top_talkers_chart(labels: list[str], values: list[float],
                      title: str = 'Top Talkers by Bytes',
                      xlabel: str = 'Total Bytes') -> str:
    """
    Horizontal bar chart: top N hosts/domains/endpoints by a numeric value.
    Returns base64 PNG.
    """
    n = len(labels)
    height = max(2.5, n * 0.4)
    fig, ax = make_figure(width_in=7.5, height_in=height)

    if not labels:
        ax.text(0.5, 0.5, 'No data', ha='center', va='center', transform=ax.transAxes,
                color=AXIS_LABEL)
        ax.set_axis_off()
    else:
        y_pos = range(n - 1, -1, -1)  # top item at top
        bars = ax.barh(list(y_pos), values, color=PRIMARY, height=0.6, zorder=3)
        ax.set_yticks(list(y_pos))
        ax.set_yticklabels(labels, fontsize=8)
        ax.xaxis.set_major_formatter(mticker.FuncFormatter(
            lambda x, _: f'{x/1e9:.1f}GB' if x >= 1e9
            else f'{x/1e6:.1f}MB' if x >= 1e6
            else f'{x/1e3:.0f}KB'
        ))
        apply_base_style(ax, title=title, xlabel=xlabel)

    fig.tight_layout(pad=1.0)
    return _fig_to_b64(fig)


def latency_percentile_chart(time_labels: list[str], p50: list[float],
                              p95: list[float], p99: list[float],
                              title: str = 'Latency Percentiles') -> str:
    """
    Multi-line chart: p50, p95, p99 latency over time.
    Returns base64 PNG.
    """
    fig, ax = make_figure(width_in=7.5, height_in=3.0)
    x = range(len(time_labels)) if time_labels else []

    if p50:  ax.plot(x, p50, color=SUCCESS,   linewidth=1.5, label='p50')
    if p95:  ax.plot(x, p95, color=WARNING,   linewidth=1.5, label='p95')
    if p99:  ax.plot(x, p99, color=DANGER,    linewidth=1.5, label='p99', linestyle='--')

    apply_base_style(ax, title=title, ylabel='Latency (ms)')

    if time_labels:
        step = max(1, len(time_labels) // 8)
        ax.set_xticks(range(0, len(time_labels), step))
        ax.set_xticklabels(time_labels[::step], rotation=30, ha='right', fontsize=7)

    ax.legend(loc='upper right', fontsize=8, framealpha=0.8)
    fig.tight_layout(pad=1.0)
    return _fig_to_b64(fig)


def dns_query_rate_chart(time_labels: list[str], query_counts: list[float],
                          nxdomain_counts: Optional[list[float]] = None) -> str:
    """
    Line chart: DNS query rate over time with optional NXDOMAIN overlay.
    """
    fig, ax = make_figure(width_in=7.5, height_in=3.0)
    x = range(len(time_labels)) if time_labels else []

    if query_counts:
        ax.plot(x, query_counts, color=PRIMARY, linewidth=1.5, label='Total Queries')
        ax.fill_between(x, query_counts, alpha=0.1, color=PRIMARY)
    if nxdomain_counts:
        ax.plot(x, nxdomain_counts, color=DANGER, linewidth=1.5, label='NXDOMAIN')

    apply_base_style(ax, title='DNS Query Rate', ylabel='Queries / interval')
    if time_labels:
        step = max(1, len(time_labels) // 8)
        ax.set_xticks(range(0, len(time_labels), step))
        ax.set_xticklabels(time_labels[::step], rotation=30, ha='right', fontsize=7)
    ax.legend(fontsize=8, framealpha=0.8)
    fig.tight_layout(pad=1.0)
    return _fig_to_b64(fig)


def error_rate_chart(time_labels: list[str], error_rates: list[float],
                     title: str = 'Error Rate (%)') -> str:
    """
    Area chart: error rate over time.
    """
    fig, ax = make_figure(width_in=7.5, height_in=2.5)
    x = range(len(time_labels)) if time_labels else []
    if error_rates:
        ax.plot(x, error_rates, color=DANGER, linewidth=1.5)
        ax.fill_between(x, error_rates, alpha=0.2, color=DANGER)
    apply_base_style(ax, title=title, ylabel='Error Rate (%)')
    if time_labels:
        step = max(1, len(time_labels) // 8)
        ax.set_xticks(range(0, len(time_labels), step))
        ax.set_xticklabels(time_labels[::step], rotation=30, ha='right', fontsize=7)
    fig.tight_layout(pad=1.0)
    return _fig_to_b64(fig)


def alert_timeline_chart(alert_times: list[str], severities: list[str],
                          alert_titles: list[str]) -> str:
    """
    Scatter/timeline chart: shows when each alert fired and its severity.
    """
    color_map = {'CRITICAL': DANGER, 'WARNING': WARNING, 'INFO': SECONDARY}
    fig, ax = make_figure(width_in=7.5, height_in=max(2.5, len(alert_times) * 0.3 + 1.0))

    for i, (t, sev, title) in enumerate(zip(alert_times, severities, alert_titles)):
        color = color_map.get(sev, SECONDARY)
        ax.barh(i, 1, left=0, color=color, height=0.6, zorder=3)
        ax.text(1.05, i, f'{t} — {title[:50]}', va='center', fontsize=7, color=TITLE_COLOR)

    ax.set_yticks(range(len(alert_times)))
    ax.set_yticklabels([s for s in severities], fontsize=7)
    ax.set_xlim(0, 1)
    ax.xaxis.set_visible(False)
    apply_base_style(ax, title='Alert Timeline')

    legend_patches = [
        Patch(color=DANGER, label='Critical'),
        Patch(color=WARNING, label='Warning'),
        Patch(color=SECONDARY, label='Info'),
    ]
    ax.legend(handles=legend_patches, loc='lower right', fontsize=8)
    fig.tight_layout(pad=1.0)
    return _fig_to_b64(fig)


def rca_correlation_chart(time_labels: list[str],
                           series: dict[str, list[float]],
                           alert_time_idx: Optional[int] = None) -> str:
    """
    Multi-series line chart for RCA: RTT, retransmit rate, error rate, DNS latency
    all on one chart with a shared time axis and a vertical line at the alert time.
    """
    n = len(series)
    fig, axes = make_figure_multi(n, 1, width_in=7.5, height_in=n * 1.8)
    if n == 1:
        axes = [axes]

    x = range(len(time_labels)) if time_labels else []

    for idx, (name, values) in enumerate(series.items()):
        ax = axes[idx]
        color = SERIES_COLORS[idx % len(SERIES_COLORS)]
        if values:
            ax.plot(x, values, color=color, linewidth=1.5)
            ax.fill_between(x, values, alpha=0.1, color=color)
        if alert_time_idx is not None and alert_time_idx < len(x):
            ax.axvline(x=alert_time_idx, color=DANGER, linewidth=1.5,
                       linestyle='--', alpha=0.8, label='Alert fired')
        apply_base_style(ax, title=name)
        if time_labels:
            step = max(1, len(time_labels) // 6)
            ax.set_xticks(range(0, len(time_labels), step))
            ax.set_xticklabels(time_labels[::step], rotation=30, ha='right', fontsize=7)
        if idx == 0 and alert_time_idx is not None:
            ax.legend(fontsize=8)

    fig.suptitle('Incident Metric Correlation', color=TITLE_COLOR,
                 fontsize=12, fontweight='bold', y=1.01)
    fig.tight_layout(pad=1.0)
    return _fig_to_b64(fig)
