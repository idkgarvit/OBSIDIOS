"""SENTINEL — Real-time Suricata alert pipeline.

Spawns Suricata, tails eve.json, matches alerts against FORGE rules,
cross-references with PHANTOM attack paths, writes to sentinel_alerts,
and triggers SHIELD auto-response.
"""

from sentinel.runner import start_sentinel

__all__ = ["start_sentinel"]