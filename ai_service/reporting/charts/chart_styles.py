"""Shared Matplotlib chart styles.
All charts in all reports use these consistent style settings.
"""
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend — required for server use
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# ── Color palette (matches Tailwind slate/blue dashboard) ─────────────────────
PRIMARY       = "#2563eb"   # blue-600
SECONDARY     = "#94a3b8"   # slate-400
DANGER        = "#dc2626"   # red-600
WARNING       = "#d97706"   # amber-600
SUCCESS       = "#16a34a"   # green-600
BG_WHITE      = "#ffffff"
GRID_COLOR    = "#f1f5f9"   # slate-100
AXIS_LABEL    = "#475569"   # slate-600
TITLE_COLOR   = "#0f172a"   # slate-900
FWD_COLOR     = "#3b82f6"   # blue-500 (forward/sent)
REV_COLOR     = "#cbd5e1"   # slate-300 (reverse/received)
AMBER_HIGH    = "#fef3c7"   # amber-100 (highlight background for slow endpoints)

# Series colors for multi-series charts
SERIES_COLORS = [PRIMARY, DANGER, SUCCESS, WARNING, SECONDARY,
                 "#7c3aed", "#0891b2", "#be185d"]


def apply_base_style(ax, title: str = "", xlabel: str = "", ylabel: str = ""):
    """Apply the shared style to a matplotlib axes object."""
    ax.set_facecolor(BG_WHITE)
    ax.figure.patch.set_facecolor(BG_WHITE)
    ax.grid(True, color=GRID_COLOR, linewidth=0.8, linestyle='-', zorder=0)
    ax.set_axisbelow(True)

    # Spines
    for spine in ['top', 'right']:
        ax.spines[spine].set_visible(False)
    for spine in ['left', 'bottom']:
        ax.spines[spine].set_color(GRID_COLOR)

    # Labels
    ax.tick_params(colors=AXIS_LABEL, labelsize=8)
    if xlabel:
        ax.set_xlabel(xlabel, color=AXIS_LABEL, fontsize=9)
    if ylabel:
        ax.set_ylabel(ylabel, color=AXIS_LABEL, fontsize=9)
    if title:
        ax.set_title(title, color=TITLE_COLOR, fontsize=11, fontweight='bold', pad=10)


def make_figure(width_in: float = 7.5, height_in: float = 3.5):
    """Create a new figure with standard DPI and white background."""
    fig, ax = plt.subplots(figsize=(width_in, height_in), dpi=120)
    fig.patch.set_facecolor(BG_WHITE)
    return fig, ax


def make_figure_multi(nrows: int, ncols: int, width_in: float = 7.5, height_in: float = 5.0):
    """Create a multi-subplot figure."""
    fig, axes = plt.subplots(nrows, ncols, figsize=(width_in, height_in), dpi=120)
    fig.patch.set_facecolor(BG_WHITE)
    return fig, axes
