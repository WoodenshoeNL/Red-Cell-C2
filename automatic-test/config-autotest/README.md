# automatic-test/config-autotest/

Harness configuration used by `loop.py --loop autotest`.  Pairs with
`profiles/autotest.yaotl` (teamserver port `40156`, default listener port
`19200`), kept separate from `automatic-test/config/` so the autotest loop
cannot collide with manual `python3 test.py` runs against the regular
test profile (`profiles/test.yaotl`, port `40056`).

## First-time setup on a new machine

```bash
cd automatic-test/config-autotest

# 1. Copy the env.toml template and set callback_host to this dev-box's IP
cp env.toml.example env.toml
$EDITOR env.toml          # uncomment + fill in [server].callback_host

# 2. Symlink targets.toml from the main harness config (same VMs)
ln -s ../config/targets.toml targets.toml
```

`env.toml` and `targets.toml` are gitignored at this path, same as the
parallel files under `automatic-test/config/`.

## Running the autotest loop

```bash
./loop.py --agent claude --loop autotest                 # 4h cadence
./loop.py --agent claude --loop autotest --iterations 1  # one-shot
```

The loop:

1. Compiles `red-cell` + `red-cell-cli` (skip if source unchanged).
2. Kills any teamserver bound to `:40156`, starts a fresh one with
   `profiles/autotest.yaotl`, polls until ready.
3. SSHes into each target VM and `pkill`s any orphaned `agent-*` payloads
   from a previous interrupted run.
4. Dispatches the agent with `RC_AUTOTEST_BUILD_OK`,
   `RC_AUTOTEST_BUILD_LOG`, and `RC_AUTOTEST_CONFIG_DIR` set so the agent
   knows whether to run scenarios or troubleshoot a build failure.

The teamserver is left running between iterations so operator-side
inspection (`red-cell-cli agent list`, `red-cell-cli log list`) works
between runs without re-bootstrapping.

## Manual run

```bash
cd automatic-test
python3 test.py --config-dir config-autotest --scenario all
```

This works as long as the autotest teamserver is running on `:40156`
(the loop leaves it up; otherwise start it manually with
`./target/release/red-cell --profile profiles/autotest.yaotl`).

The regular `python3 test.py --scenario all` still uses the default
`automatic-test/config/` against `profiles/test.yaotl` on `:40056`.
