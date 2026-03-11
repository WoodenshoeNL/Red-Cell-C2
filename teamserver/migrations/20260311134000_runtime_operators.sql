CREATE TABLE IF NOT EXISTS ts_runtime_operators (
    username TEXT PRIMARY KEY NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL
);
