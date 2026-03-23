-- Payload build jobs and finished artifacts.

CREATE TABLE ts_payload_builds (
    id          TEXT    PRIMARY KEY NOT NULL,
    -- "pending", "running", "done", "error"
    status      TEXT    NOT NULL DEFAULT 'pending',
    -- Display name for the finished payload (e.g. "demon.x64.exe").
    name        TEXT    NOT NULL DEFAULT '',
    -- Target CPU architecture ("x64", "x86").
    arch        TEXT    NOT NULL,
    -- Requested output format ("exe", "dll", "bin").
    format      TEXT    NOT NULL,
    -- Name of the listener to embed in the payload.
    listener    TEXT    NOT NULL,
    -- Optional sleep interval requested by the operator.
    sleep_secs  INTEGER,
    -- Final compiled payload bytes (NULL until build completes).
    artifact    BLOB,
    -- Size of the artifact in bytes (NULL until build completes).
    size_bytes  INTEGER,
    -- Error message if the build failed.
    error       TEXT,
    -- RFC 3339 timestamps.
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);
