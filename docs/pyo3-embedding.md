# PyO3 Embedded Python on Linux — Linking Behavior

## Summary

Both `red-cell` (teamserver) and `red-cell-client` embed a Python interpreter via
PyO3 0.23 with the `abi3-py310` feature. On Linux, this **still requires a versioned
`libpython3.X.so`** at both build time and runtime. This is expected behavior, not a
bug.

## Why abi3 does not remove the versioned-library dependency

The `abi3` (stable ABI) feature controls two things:

1. **C API surface**: Rust code only calls functions in the
   [Limited API](https://docs.python.org/3/c-api/stable.html), which is
   forward-compatible across minor Python versions.
2. **Extension module naming**: A `.so` extension module built with abi3 uses the
   tag `.abi3.so` instead of `.cpython-312-x86_64-linux-gnu.so`, so one wheel works
   with Python 3.10, 3.11, 3.12, etc.

Neither of these changes **embedding** behavior. When an executable embeds Python
(as opposed to being loaded *by* Python), the linker must resolve a concrete
`libpython3.X.so` — there is no "version-free" libpython to link against.

PyO3's build script (`pyo3-ffi/build.rs`) probes the host interpreter, discovers
its version (e.g. 3.12), and emits:

```
cargo:rustc-link-lib=python3.12
cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu
```

This is correct and expected.

## Build-time requirements

The linker needs an unversioned symlink so `-lpython3.12` resolves:

```
/usr/lib/x86_64-linux-gnu/libpython3.12.so -> libpython3.12.so.1.0
```

On Debian/Ubuntu, this symlink is provided by `libpython3.12-dev`. The project's
`install.sh` creates it automatically if missing, so installing the `-dev` package
is not required when using the installer.

## Runtime requirements

At runtime, the dynamic linker resolves the SONAME `libpython3.12.so.1.0`. This
file ships in the base `libpython3.12` package (or is installed by `uv python
install 3.12`). No `-dev` package is needed at runtime.

The `install.sh` script registers the uv-managed Python's lib directory with
`ldconfig` so the runtime linker can find it.

## Chosen approach

This project uses **`install.sh` with uv-managed Python**:

1. `uv python install 3.12` provides the interpreter and shared library.
2. The installer creates the unversioned `.so` symlink for build-time linking.
3. The installer registers the lib directory with `ldconfig` for runtime linking.

This avoids requiring `libpython3.12-dev` while keeping the build portable.

### Alternatives considered

| Approach | Verdict |
|---|---|
| Require `libpython3.12-dev` | Ties builds to distro packaging; uv approach is more portable |
| Runtime `dlopen` (no link-time dependency) | PyO3 embedding does not support this; would need a custom FFI layer |
| Static linking (`libpython3.12.a`) | Increases binary size ~15 MB; license implications; complicates plugin loading |
| `.cargo/config.toml` with `-L` to local symlink dir | Works but hardcodes machine-local paths; fragile across machines |

## .cargo/config.toml

The previous workaround added a machine-local `-L` flag pointing to
`.cargo/lib/libpython3.12.so` (a symlink). This is no longer needed because:

- PyO3's build script already emits the correct `-L` path to the system lib dir.
- `install.sh` ensures the unversioned symlink exists in that directory.

The hardcoded path has been removed. If you need a custom Python, set the
`PYO3_PYTHON` environment variable instead:

```bash
PYO3_PYTHON=/path/to/python3.12 cargo build --workspace
```

## Upgrading Python

When moving to a newer Python (e.g. 3.13):

1. Update `uv python install 3.13` in `install.sh`.
2. Update the symlink creation to target `libpython3.13.so.1.0`.
3. The PyO3 `abi3-py310` feature does not need to change — it sets the *minimum*
   version, not the linked version. Any Python >= 3.10 works.
4. Rebuild: `cargo clean && cargo build --workspace`.
