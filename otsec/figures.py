"""Rendering helpers shared by notebooks and README."""
from __future__ import annotations

import subprocess

from .model import IMG


def render(dot: str, name: str):
    """Renders Graphviz DOT to docs/img/<name>.png (needs the `dot` binary)."""
    IMG.mkdir(parents=True, exist_ok=True)
    out = IMG / f"{name}.png"
    subprocess.run(["dot", "-Tpng", "-Gdpi=120", "-o", str(out)], input=dot.encode(), check=True)
    return out


def save(fig, name: str):
    IMG.mkdir(parents=True, exist_ok=True)
    out = IMG / f"{name}.png"
    fig.savefig(out, dpi=130, bbox_inches="tight")
    return out
