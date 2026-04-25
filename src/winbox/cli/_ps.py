"""CLI back-compat shim. Real helpers now live in ``winbox.ps``.

Kept as a re-export so existing ``from winbox.cli._ps import ...`` lines
stay working. New code should import from ``winbox.ps`` directly.
"""

from winbox.ps import load_ps, ps_array, ps_int_array, ps_quote, render_ps

__all__ = ["load_ps", "render_ps", "ps_quote", "ps_array", "ps_int_array"]
