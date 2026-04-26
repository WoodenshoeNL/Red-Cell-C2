"""
Parallel payload build helpers for the automated test harness.

Uses ``payload build --detach`` plus ``payload build-wait`` so a matrix of
independent payload variants can be compiled concurrently on the teamserver
instead of serially paying the sum of all compile times.
"""

from __future__ import annotations

import os
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Sequence

from lib.cli import (
    PAYLOAD_BUILD_WAIT_TIMEOUT_SECS,
    CliConfig,
    payload_build,
    payload_build_wait,
    payload_download,
)


@dataclass(frozen=True)
class MatrixCell:
    """One cell in a payload build matrix (e.g. arch × format)."""

    arch: str = "x64"
    fmt: str = "exe"
    agent: str = "demon"
    sleep_secs: int | None = None
    listener: str | None = None


def _normalize_cell(c: MatrixCell | tuple[Any, ...] | list[Any]) -> MatrixCell:
    if isinstance(c, MatrixCell):
        return c
    if isinstance(c, (tuple, list)):
        n = len(c)
        if n == 2:
            a, f = c[0], c[1]
            return MatrixCell(arch=str(a), fmt=str(f), agent="demon", sleep_secs=None)
        if n == 3:
            a, f, ag = c[0], c[1], c[2]
            return MatrixCell(arch=str(a), fmt=str(f), agent=str(ag), sleep_secs=None)
        if n == 4:
            a, f, ag, s = c[0], c[1], c[2], c[3]
            return MatrixCell(arch=str(a), fmt=str(f), agent=str(ag), sleep_secs=s)
    raise TypeError(
        f"expected MatrixCell or (arch, fmt[, agent[, sleep_secs]]), got {c!r}"
    )


def _one_cell_bytes(
    cfg: CliConfig,
    listener: str,
    cell: MatrixCell,
) -> bytes:
    """Detach-submit, wait, and download a single build (caller threads this)."""
    effective_listener = cell.listener if cell.listener is not None else listener
    sub = payload_build(
        cfg,
        listener=effective_listener,
        arch=cell.arch,
        fmt=cell.fmt,
        agent=cell.agent,
        sleep_secs=cell.sleep_secs,
        wait=False,
        detach=True,
    )
    job_id = sub["job_id"]
    # Wait and download: build-wait without --output, then download to a temp file.
    done = payload_build_wait(
        cfg,
        job_id,
        wait_timeout_secs=PAYLOAD_BUILD_WAIT_TIMEOUT_SECS,
    )
    payload_id = str(done["payload_id"])
    fd, tmp_path = tempfile.mkstemp(suffix=f".{cell.fmt}")
    os.close(fd)
    try:
        payload_download(cfg, payload_id, tmp_path)
        with open(tmp_path, "rb") as fh:
            return fh.read()
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def build_parallel(
    cfg: CliConfig,
    listener: str,
    cells: Sequence[MatrixCell | tuple[Any, ...] | list[Any]],
    *,
    parallel: bool = True,
) -> list[bytes]:
    """Build each matrix *cell* and return raw artifact bytes in the same order.

    When *parallel* is True, submissions and waits are run in a thread pool so
    the teamserver can compile all variants together (wall-clock ≈ slowest
    build).  When *parallel* is False, runs ``payload build --wait`` + download
    for each cell sequentially (handy for debugging).
    """
    if not cells:
        return []
    row: list[MatrixCell] = [_normalize_cell(c) for c in cells]

    if not parallel:
        from lib.cli import payload_build_and_fetch

        out: list[bytes] = []
        for cell in row:
            effective_listener = cell.listener if cell.listener is not None else listener
            out.append(
                payload_build_and_fetch(
                    cfg,
                    listener=effective_listener,
                    arch=cell.arch,
                    fmt=cell.fmt,
                    agent=cell.agent,
                    sleep_secs=cell.sleep_secs,
                )
            )
        return out

    n = len(row)
    # Up to one thread per cell — the expensive work is server-side; clients only poll.
    with ThreadPoolExecutor(max_workers=n) as ex:
        futs = {
            ex.submit(_one_cell_bytes, cfg, listener, cell): i for i, cell in enumerate(row)
        }
        buf: list[bytes] = [b""] * n
        for fut in as_completed(futs):
            i = futs[fut]
            buf[i] = fut.result()
    return buf
