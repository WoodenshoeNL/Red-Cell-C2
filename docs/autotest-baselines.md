# Autotest Wall-Clock Baselines

Measured on `Ubuntu-C2-dev01-tnpl` (16 GB RAM, release build).
Serial mode (`--no-parallel`) — the parallel path requires `--detach` (not yet in CLI).

| Date       | Scenario 03 (s) | Full Suite (s) | Notes                          |
|------------|------------------|----------------|--------------------------------|
| 2026-04-24 | 244              | —              | Pre-st563 baseline (estimated) |
| 2026-04-26 | 242.5            | 747.8          | Post-st563, serial mode        |
