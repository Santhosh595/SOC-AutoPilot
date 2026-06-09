import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch


BACKGROUND_COLOR = "#1a1a2e"
BOX_COLOR = "#16213e"
ARROW_COLOR = "#00d4ff"
TEXT_COLOR = "white"


def draw_box(ax, center, text, width=2.4, height=0.75):
    """Draw a labeled rounded box centered at the given coordinates."""
    x, y = center
    box = FancyBboxPatch(
        (x - width / 2, y - height / 2),
        width,
        height,
        boxstyle="round,pad=0.03,rounding_size=0.08",
        linewidth=1.6,
        edgecolor=ARROW_COLOR,
        facecolor=BOX_COLOR,
    )
    ax.add_patch(box)
    ax.text(
        x,
        y,
        text,
        ha="center",
        va="center",
        color=TEXT_COLOR,
        fontsize=12,
        fontweight="bold",
    )


def draw_arrow(ax, start, end, bidirectional=False):
    """Draw a directional or bidirectional arrow between two points."""
    arrowstyle = "<->" if bidirectional else "->"
    arrow = FancyArrowPatch(
        start,
        end,
        arrowstyle=arrowstyle,
        mutation_scale=18,
        linewidth=2,
        color=ARROW_COLOR,
        shrinkA=18,
        shrinkB=18,
    )
    ax.add_patch(arrow)


def main():
    """Generate the SOC AutoPilot architecture diagram."""
    fig, ax = plt.subplots(figsize=(12, 7), facecolor=BACKGROUND_COLOR)
    ax.set_facecolor(BACKGROUND_COLOR)
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 8)
    ax.axis("off")

    positions = {
        "alert": (6, 6.7),
        "splunk": (2.2, 4.2),
        "agent": (6, 4.2),
        "gemini": (9.8, 4.2),
        "kb": (3.8, 1.7),
        "reports": (8.2, 1.7),
    }

    ax.text(
        6,
        7.6,
        "SOC AutoPilot — Architecture",
        ha="center",
        va="center",
        color=TEXT_COLOR,
        fontsize=22,
        fontweight="bold",
    )

    draw_box(ax, positions["alert"], "Alert Input")
    draw_box(ax, positions["splunk"], "Splunk MCP Server")
    draw_box(ax, positions["agent"], "AutoPilot Agent")
    draw_box(ax, positions["gemini"], "Gemini Flash AI")
    draw_box(ax, positions["kb"], "Knowledge Base\n(SQLite)")
    draw_box(ax, positions["reports"], "Reports + SPL Rules")

    draw_arrow(ax, positions["alert"], positions["agent"])
    draw_arrow(ax, positions["agent"], positions["splunk"], bidirectional=True)
    draw_arrow(ax, positions["agent"], positions["gemini"], bidirectional=True)
    draw_arrow(ax, positions["agent"], positions["kb"], bidirectional=True)
    draw_arrow(ax, positions["agent"], positions["reports"])

    plt.tight_layout()
    plt.savefig("architecture.png", dpi=200, facecolor=BACKGROUND_COLOR)
    plt.close(fig)
    print("architecture.png saved")


if __name__ == "__main__":
    main()
