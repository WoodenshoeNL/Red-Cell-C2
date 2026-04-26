"""
Helpers for loading harness config into `red-cell-cli` wrapper objects.

``env.toml`` and ``targets.toml`` are validated at load time against the
dataclass schemas below so typos and wrong types fail fast with a clear
:class:`ConfigError` instead of mid-scenario :class:`KeyError` tracebacks.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
import tomllib
from typing import Any, Iterable

from .cli import CliConfig


# ── Schema (stdlib dataclasses, no external deps) ───────────────────────────


class ConfigError(Exception):
    """Raised when ``env.toml`` or ``targets.toml`` does not match the schema."""

    def __init__(self, messages: list[str]) -> None:
        self.messages = messages
        super().__init__(self._format())

    def _format(self) -> str:
        return "Configuration validation failed:\n  - " + "\n  - ".join(self.messages)


@dataclass
class ServerConfig:
    url: str
    rest_url: str | None = None
    cert_fingerprint: str | None = None
    callback_host: str | None = None


@dataclass
class OperatorConfig:
    username: str
    api_key: str
    password: str | None = None


@dataclass
class TimeoutsConfig:
    """Resolved harness timeouts (seconds unless noted).

    TOML may use ``*_secs`` names for the primary tunables; legacy names without
    the suffix remain accepted — see :func:`parse_env_config`.
    """

    agent_checkin: float
    command_output: float
    agent_disconnect: float
    screenshot_loot: float
    loot_entry: float
    max_cli_subprocess_secs: float
    #: After ``listener start``, wait up to this many seconds for TCP (HTTP lifecycle).
    listener_startup: float
    #: Default interval for :func:`lib.wait.poll` / stress polling when not overridden.
    poll_interval: float
    #: ``ssh``/``scp`` ``ConnectTimeout=`` (seconds).
    ssh_connect: float
    #: Wall-clock timeout for SCP upload/download subprocesses.
    scp_transfer: float
    #: Scenario 14: deadline for *all* concurrent agents to check in.
    stress_concurrent_checkin: float
    resilience_reconnect: float | None = None
    resilience_kill_date: float | None = None
    working_hours_probe: float | None = None


def timeouts_for_unit_tests() -> TimeoutsConfig:
    """Stable :class:`TimeoutsConfig` for unit tests that mock :class:`RunContext` without ``env.toml``."""

    return TimeoutsConfig(
        agent_checkin=60.0,
        command_output=30.0,
        agent_disconnect=30.0,
        screenshot_loot=30.0,
        loot_entry=30.0,
        max_cli_subprocess_secs=120.0,
        listener_startup=5.0,
        poll_interval=2.0,
        ssh_connect=10.0,
        scp_transfer=60.0,
        stress_concurrent_checkin=30.0,
        resilience_reconnect=None,
        resilience_kill_date=None,
        working_hours_probe=None,
    )


@dataclass
class ListenersConfig:
    dns_port: int
    dns_domain: str
    linux_port: int
    windows_port: int
    payload_build_port: int
    protocol_probe_port: int
    interop_win_port: int
    interop_lin_port: int
    stress_demon_port: int
    stress_phantom_port: int
    rbac_admin_port: int
    rbac_viewer_port: int
    smb_pipe: str


@dataclass
class AgentsConfig:
    available: list[str]


@dataclass
class TeamserverSectionConfig:
    """Optional ``[teamserver]`` stanza — all fields optional."""

    host: str | None = None
    ssh_user: str | None = None
    ssh_port: int | None = None
    ssh_key: str | None = None
    cpu_limit_pct: float | None = None
    rss_limit_mb: float | None = None
    log_file: str | None = None


@dataclass
class AnalystOperatorConfig:
    username: str
    api_key: str


@dataclass
class ArchonSectionConfig:
    extensions: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class LinuxEnvSectionConfig:
    """Optional ``[linux]`` in env.toml (e.g. display override for screenshots)."""

    display: str | None = None


@dataclass
class KerberosSectionConfig:
    """Optional ``[kerberos]`` stanza for scenario 09 structured validation.

    When ``enabled`` is true, ``domain_realm``, ``account_name``, and a non-empty
    ``expected_groups`` list are required at load time.
    """

    enabled: bool
    domain_realm: str
    account_name: str
    expected_groups: list[str]
    expected_impersonation_level: str


@dataclass
class EnvConfig:
    server: ServerConfig
    operator: OperatorConfig
    timeouts: TimeoutsConfig
    listeners: ListenersConfig
    agents: AgentsConfig
    teamserver: TeamserverSectionConfig | None = None
    analyst_operator: AnalystOperatorConfig | None = None
    archon: ArchonSectionConfig | None = None
    linux: LinuxEnvSectionConfig | None = None
    kerberos: KerberosSectionConfig | None = None


@dataclass
class TargetSectionConfig:
    host: str
    port: int
    user: str
    work_dir: str
    key: str
    display: str | None = None


@dataclass
class TargetsConfig:
    """Parsed ``targets.toml`` when all referenced stanzas are present."""

    linux: TargetSectionConfig | None = None
    windows: TargetSectionConfig | None = None
    windows2: TargetSectionConfig | None = None


# ── Validation helpers ────────────────────────────────────────────────────────

_ALLOWED_ENV_ROOT = frozenset({
    "server",
    "operator",
    "timeouts",
    "listeners",
    "agents",
    "teamserver",
    "analyst_operator",
    "archon",
    "linux",
    "kerberos",
})

_ALLOWED_SERVER_KEYS = frozenset({"url", "rest_url", "cert_fingerprint", "callback_host"})
_ALLOWED_OPERATOR_KEYS = frozenset({"username", "password", "api_key"})
_ALLOWED_TIMEOUTS_KEYS = frozenset({
    "agent_checkin",
    "agent_checkin_secs",
    "command_output",
    "command_output_secs",
    "agent_disconnect",
    "screenshot_loot",
    "loot_entry",
    "max_cli_subprocess_secs",
    "listener_startup_secs",
    "poll_interval_secs",
    "ssh_connect_secs",
    "scp_transfer_secs",
    "stress_concurrent_checkin_secs",
    "resilience_reconnect",
    "resilience_kill_date",
    "working_hours_probe",
})
_ALLOWED_LISTENERS_KEYS = frozenset({
    "dns_port",
    "dns_domain",
    "linux_port",
    "windows_port",
    "payload_build_port",
    "protocol_probe_port",
    "interop_win_port",
    "interop_lin_port",
    "stress_demon_port",
    "stress_phantom_port",
    "rbac_admin_port",
    "rbac_viewer_port",
    "smb_pipe",
})
_ALLOWED_AGENTS_KEYS = frozenset({"available"})
_ALLOWED_TEAMSERVER_KEYS = frozenset({
    "host",
    "ssh_user",
    "ssh_port",
    "ssh_key",
    "cpu_limit_pct",
    "rss_limit_mb",
    "log_file",
})
_ALLOWED_ANALYST_KEYS = frozenset({"username", "api_key"})
_ALLOWED_ARCHON_KEYS = frozenset({"extensions"})
_ALLOWED_LINUX_ENV_KEYS = frozenset({"display"})
_ALLOWED_KERBEROS_KEYS = frozenset({
    "enabled",
    "domain_realm",
    "account_name",
    "expected_groups",
    "expected_impersonation_level",
})

# Logical required fields (each may be satisfied by ``key`` or ``key_secs`` — see parser).
_REQUIRED_TIMEOUTS_CORE = (
    "agent_disconnect",
    "screenshot_loot",
    "loot_entry",
    "max_cli_subprocess_secs",
)

_ALLOWED_TARGET_STANZAS = frozenset({"linux", "windows", "windows2"})
_ALLOWED_TARGET_KEYS = frozenset({"host", "port", "user", "work_dir", "key", "display"})


def _unknown_keys(d: dict[str, Any], allowed: Iterable[str], label: str, errors: list[str]) -> None:
    bad = sorted(set(d) - set(allowed))
    if bad:
        errors.append(f"{label}: unknown key(s): {', '.join(repr(k) for k in bad)}")


def _require_table(raw: dict[str, Any], key: str, errors: list[str]) -> dict[str, Any] | None:
    val = raw.get(key)
    if val is None:
        errors.append(f"missing required table [{key}]")
        return None
    if not isinstance(val, dict):
        errors.append(f"[{key}] must be a table, got {type(val).__name__}")
        return None
    return val


def _non_empty_str(val: Any, path: str, errors: list[str]) -> str | None:
    if not isinstance(val, str):
        errors.append(f"{path}: expected string, got {type(val).__name__}")
        return None
    if not val.strip():
        errors.append(f"{path}: must be a non-empty string")
        return None
    return val


def _optional_str(val: Any, path: str, errors: list[str]) -> str | None:
    if val is None:
        return None
    if not isinstance(val, str):
        errors.append(f"{path}: expected string or null, got {type(val).__name__}")
        return None
    return val


def _require_int(val: Any, path: str, errors: list[str]) -> int | None:
    if isinstance(val, bool) or not isinstance(val, int):
        errors.append(f"{path}: expected integer, got {type(val).__name__}")
        return None
    return val


def _require_positive_number(val: Any, path: str, errors: list[str]) -> float | None:
    if isinstance(val, bool):
        errors.append(f"{path}: expected number, got bool")
        return None
    if isinstance(val, int):
        return float(val)
    if isinstance(val, float):
        return val
    errors.append(f"{path}: expected number, got {type(val).__name__}")
    return None


def _resolve_timeout_pair(
    d: dict[str, Any],
    new_key: str,
    old_key: str,
    label: str,
    errors: list[str],
) -> float | None:
    """Prefer *new_key*; fall back to *old_key*. Error if both differ."""
    v_new = d.get(new_key)
    v_old = d.get(old_key)
    if v_new is not None and v_old is not None and v_new != v_old:
        errors.append(
            f"{label}: {new_key!r} and {old_key!r} are both set to different values — "
            "use only one"
        )
    raw = v_new if v_new is not None else v_old
    if raw is None:
        return None
    path_key = new_key if v_new is not None else old_key
    return _require_positive_number(raw, f"{label}.{path_key}", errors)


def _optional_timeout_default(
    d: dict[str, Any],
    key: str,
    default: float,
    label: str,
    errors: list[str],
) -> float:
    if key not in d or d[key] is None:
        return default
    n = _require_positive_number(d[key], f"{label}.{key}", errors)
    return default if n is None else n


def parse_env_config(raw: dict[str, Any]) -> EnvConfig:
    """Parse and validate *raw* env dict into :class:`EnvConfig`.

    Raises:
        ConfigError: If the document is invalid (missing tables, wrong types,
            unknown keys, etc.).
    """
    errors: list[str] = []

    for k in raw:
        if k not in _ALLOWED_ENV_ROOT:
            errors.append(f"unknown top-level key: {k!r}")

    server_t = _require_table(raw, "server", errors)
    if server_t is not None:
        _unknown_keys(server_t, _ALLOWED_SERVER_KEYS, "[server]", errors)
        url = _non_empty_str(server_t.get("url"), "[server].url", errors)
        rest = server_t.get("rest_url")
        rest_url = _optional_str(rest, "[server].rest_url", errors) if rest is not None else None
        fp = server_t.get("cert_fingerprint")
        cert_fingerprint = _optional_str(fp, "[server].cert_fingerprint", errors) if fp is not None else None
        ch = server_t.get("callback_host")
        callback_host = _optional_str(ch, "[server].callback_host", errors) if ch is not None else None
    else:
        url = None
        rest_url = None
        cert_fingerprint = None
        callback_host = None

    op_t = _require_table(raw, "operator", errors)
    if op_t is not None:
        _unknown_keys(op_t, _ALLOWED_OPERATOR_KEYS, "[operator]", errors)
        op_user = _non_empty_str(op_t.get("username"), "[operator].username", errors)
        api_key = _non_empty_str(op_t.get("api_key"), "[operator].api_key", errors)
        pwd = op_t.get("password")
        password = _optional_str(pwd, "[operator].password", errors) if pwd is not None else None
    else:
        op_user = api_key = password = None  # type: ignore[assignment]

    to_t = _require_table(raw, "timeouts", errors)
    tr: dict[str, float | None] = {}
    if to_t is not None:
        _unknown_keys(to_t, _ALLOWED_TIMEOUTS_KEYS, "[timeouts]", errors)
        for req in _REQUIRED_TIMEOUTS_CORE:
            if req not in to_t:
                errors.append(f"[timeouts]: missing required key {req!r}")
        for req in _REQUIRED_TIMEOUTS_CORE:
            if req in to_t:
                n = _require_positive_number(to_t[req], f"[timeouts].{req}", errors)
                tr[req] = n
        ac = _resolve_timeout_pair(
            to_t, "agent_checkin_secs", "agent_checkin", "[timeouts]", errors
        )
        if ac is None:
            errors.append("[timeouts]: need agent_checkin_secs or agent_checkin")
        else:
            tr["agent_checkin"] = ac
        co = _resolve_timeout_pair(
            to_t, "command_output_secs", "command_output", "[timeouts]", errors
        )
        if co is None:
            errors.append("[timeouts]: need command_output_secs or command_output")
        else:
            tr["command_output"] = co
        tr["listener_startup"] = _optional_timeout_default(
            to_t, "listener_startup_secs", 5.0, "[timeouts]", errors
        )
        tr["poll_interval"] = _optional_timeout_default(
            to_t, "poll_interval_secs", 2.0, "[timeouts]", errors
        )
        tr["ssh_connect"] = _optional_timeout_default(
            to_t, "ssh_connect_secs", 10.0, "[timeouts]", errors
        )
        tr["scp_transfer"] = _optional_timeout_default(
            to_t, "scp_transfer_secs", 60.0, "[timeouts]", errors
        )
        tr["stress_concurrent_checkin"] = _optional_timeout_default(
            to_t, "stress_concurrent_checkin_secs", 30.0, "[timeouts]", errors
        )
        for opt in ("resilience_reconnect", "resilience_kill_date", "working_hours_probe"):
            if opt in to_t and to_t[opt] is not None:
                tr[opt] = _require_positive_number(to_t[opt], f"[timeouts].{opt}", errors)
            else:
                tr[opt] = None
    else:
        pass

    li_t = _require_table(raw, "listeners", errors)
    if li_t is not None:
        _unknown_keys(li_t, _ALLOWED_LISTENERS_KEYS, "[listeners]", errors)
        dns_port = _require_int(li_t.get("dns_port"), "[listeners].dns_port", errors)
        dns_domain = _non_empty_str(li_t.get("dns_domain"), "[listeners].dns_domain", errors)
        linux_port = _require_int(li_t.get("linux_port"), "[listeners].linux_port", errors)
        windows_port = _require_int(li_t.get("windows_port"), "[listeners].windows_port", errors)
        payload_build_port = _require_int(
            li_t.get("payload_build_port"), "[listeners].payload_build_port", errors
        )
        protocol_probe_port = _require_int(
            li_t.get("protocol_probe_port"), "[listeners].protocol_probe_port", errors
        )
        interop_win_port = _require_int(
            li_t.get("interop_win_port"), "[listeners].interop_win_port", errors
        )
        interop_lin_port = _require_int(
            li_t.get("interop_lin_port"), "[listeners].interop_lin_port", errors
        )
        stress_demon_port = _require_int(
            li_t.get("stress_demon_port"), "[listeners].stress_demon_port", errors
        )
        stress_phantom_port = _require_int(
            li_t.get("stress_phantom_port"), "[listeners].stress_phantom_port", errors
        )
        rbac_admin_port = _require_int(
            li_t.get("rbac_admin_port"), "[listeners].rbac_admin_port", errors
        )
        rbac_viewer_port = _require_int(
            li_t.get("rbac_viewer_port"), "[listeners].rbac_viewer_port", errors
        )
        smb_pipe = _non_empty_str(li_t.get("smb_pipe"), "[listeners].smb_pipe", errors)
    else:
        dns_port = dns_domain = linux_port = windows_port = None  # type: ignore[assignment]
        payload_build_port = protocol_probe_port = interop_win_port = None  # type: ignore[assignment]
        interop_lin_port = stress_demon_port = stress_phantom_port = rbac_admin_port = rbac_viewer_port = smb_pipe = None  # type: ignore[assignment]

    ag_t = _require_table(raw, "agents", errors)
    if ag_t is not None:
        _unknown_keys(ag_t, _ALLOWED_AGENTS_KEYS, "[agents]", errors)
        avail = ag_t.get("available")
        if not isinstance(avail, list) or not all(isinstance(x, str) for x in avail):
            errors.append("[agents].available must be a list of strings")
            available_list: list[str] | None = None
        else:
            available_list = list(avail)
    else:
        available_list = None

    teamserver_obj: TeamserverSectionConfig | None = None
    if "teamserver" in raw:
        ts = raw["teamserver"]
        if ts is None or (isinstance(ts, dict) and len(ts) == 0):
            teamserver_obj = TeamserverSectionConfig()
        elif isinstance(ts, dict):
            _unknown_keys(ts, _ALLOWED_TEAMSERVER_KEYS, "[teamserver]", errors)
            ssh_port_raw = ts.get("ssh_port")
            ssh_port = _require_int(ssh_port_raw, "[teamserver].ssh_port", errors) if ssh_port_raw is not None else None
            cpu_raw = ts.get("cpu_limit_pct")
            rss_raw = ts.get("rss_limit_mb")
            teamserver_obj = TeamserverSectionConfig(
                host=_optional_str(ts.get("host"), "[teamserver].host", errors),
                ssh_user=_optional_str(ts.get("ssh_user"), "[teamserver].ssh_user", errors),
                ssh_port=ssh_port,
                ssh_key=_optional_str(ts.get("ssh_key"), "[teamserver].ssh_key", errors),
                cpu_limit_pct=_require_positive_number(cpu_raw, "[teamserver].cpu_limit_pct", errors)
                if cpu_raw is not None
                else None,
                rss_limit_mb=_require_positive_number(rss_raw, "[teamserver].rss_limit_mb", errors)
                if rss_raw is not None and rss_raw != ""
                else None,
                log_file=_optional_str(ts.get("log_file"), "[teamserver].log_file", errors),
            )
        else:
            errors.append(f"[teamserver] must be a table or empty, got {type(ts).__name__}")

    analyst_obj: AnalystOperatorConfig | None = None
    if "analyst_operator" in raw:
        ao = raw["analyst_operator"]
        if isinstance(ao, dict):
            _unknown_keys(ao, _ALLOWED_ANALYST_KEYS, "[analyst_operator]", errors)
            au = _non_empty_str(ao.get("username"), "[analyst_operator].username", errors)
            ak = ao.get("api_key", "")
            if not isinstance(ak, str):
                errors.append(f"[analyst_operator].api_key: expected string, got {type(ak).__name__}")
            elif au is not None:
                analyst_obj = AnalystOperatorConfig(username=au, api_key=ak)
        else:
            errors.append(f"[analyst_operator] must be a table, got {type(ao).__name__}")

    archon_obj: ArchonSectionConfig | None = None
    if "archon" in raw:
        ar = raw["archon"]
        if isinstance(ar, dict):
            _unknown_keys(ar, _ALLOWED_ARCHON_KEYS, "[archon]", errors)
            ext = ar.get("extensions", [])
            if not isinstance(ext, list):
                errors.append("[archon].extensions must be a list")
            elif not all(isinstance(x, dict) for x in ext):
                errors.append("[archon].extensions must be a list of tables")
            else:
                archon_obj = ArchonSectionConfig(extensions=list(ext))
        else:
            errors.append(f"[archon] must be a table, got {type(ar).__name__}")

    linux_env_obj: LinuxEnvSectionConfig | None = None
    if "linux" in raw:
        lx = raw["linux"]
        if isinstance(lx, dict):
            _unknown_keys(lx, _ALLOWED_LINUX_ENV_KEYS, "[linux]", errors)
            disp = lx.get("display")
            if disp is not None and not isinstance(disp, str):
                errors.append(f"[linux].display: expected string, got {type(disp).__name__}")
            else:
                linux_env_obj = LinuxEnvSectionConfig(display=disp)
        else:
            errors.append(f"[linux] must be a table, got {type(lx).__name__}")

    kerberos_obj: KerberosSectionConfig | None = None
    if "kerberos" in raw:
        kr = raw["kerberos"]
        if kr is None:
            errors.append("[kerberos] must be a table or omitted")
        elif not isinstance(kr, dict):
            errors.append(f"[kerberos] must be a table, got {type(kr).__name__}")
        elif len(kr) == 0:
            kerberos_obj = None
        else:
            _unknown_keys(kr, _ALLOWED_KERBEROS_KEYS, "[kerberos]", errors)
            en_raw = kr.get("enabled", True)
            if isinstance(en_raw, bool):
                enabled_k = en_raw
            else:
                errors.append(
                    "[kerberos].enabled: expected boolean, got "
                    f"{type(en_raw).__name__}"
                )
                enabled_k = False
            dr_raw = kr.get("domain_realm", "")
            an_raw = kr.get("account_name", "")
            eg_raw = kr.get("expected_groups", [])
            ei_raw = kr.get("expected_impersonation_level", "Identification")

            if not isinstance(dr_raw, str):
                errors.append("[kerberos].domain_realm: expected string")
                dr = ""
            else:
                dr = dr_raw.strip()
            if not isinstance(an_raw, str):
                errors.append("[kerberos].account_name: expected string")
                an = ""
            else:
                an = an_raw.strip()

            if not isinstance(eg_raw, list) or not all(isinstance(x, str) for x in eg_raw):
                errors.append("[kerberos].expected_groups must be a list of strings")
                eg_list: list[str] = []
            else:
                eg_list = [str(x).strip() for x in eg_raw if str(x).strip()]

            if not isinstance(ei_raw, str):
                errors.append("[kerberos].expected_impersonation_level: expected string")
                ei = "Identification"
            else:
                ei = ei_raw.strip() or "Identification"

            if enabled_k:
                if not dr:
                    errors.append("[kerberos].domain_realm: required when enabled = true")
                if not an:
                    errors.append("[kerberos].account_name: required when enabled = true")
                if not eg_list:
                    errors.append(
                        "[kerberos].expected_groups: non-empty list required when "
                        "enabled = true"
                    )
            kerberos_obj = KerberosSectionConfig(
                enabled=enabled_k,
                domain_realm=dr,
                account_name=an,
                expected_groups=eg_list,
                expected_impersonation_level=ei,
            )

    if errors:
        raise ConfigError(errors)

    assert url is not None and op_user is not None and api_key is not None
    assert tr.get("agent_checkin") is not None and tr.get("command_output") is not None
    assert available_list is not None
    assert dns_port is not None and smb_pipe is not None

    return EnvConfig(
        server=ServerConfig(url=url, rest_url=rest_url, cert_fingerprint=cert_fingerprint, callback_host=callback_host),
        operator=OperatorConfig(username=op_user, api_key=api_key, password=password),
        timeouts=TimeoutsConfig(
            agent_checkin=tr["agent_checkin"],  # type: ignore[arg-type]
            command_output=tr["command_output"],  # type: ignore[arg-type]
            agent_disconnect=tr["agent_disconnect"],  # type: ignore[arg-type]
            screenshot_loot=tr["screenshot_loot"],  # type: ignore[arg-type]
            loot_entry=tr["loot_entry"],  # type: ignore[arg-type]
            max_cli_subprocess_secs=tr["max_cli_subprocess_secs"],  # type: ignore[arg-type]
            listener_startup=tr["listener_startup"],  # type: ignore[arg-type]
            poll_interval=tr["poll_interval"],  # type: ignore[arg-type]
            ssh_connect=tr["ssh_connect"],  # type: ignore[arg-type]
            scp_transfer=tr["scp_transfer"],  # type: ignore[arg-type]
            stress_concurrent_checkin=tr["stress_concurrent_checkin"],  # type: ignore[arg-type]
            resilience_reconnect=tr.get("resilience_reconnect"),
            resilience_kill_date=tr.get("resilience_kill_date"),
            working_hours_probe=tr.get("working_hours_probe"),
        ),
        listeners=ListenersConfig(
            dns_port=dns_port,
            dns_domain=dns_domain,  # type: ignore[arg-type]
            linux_port=linux_port,  # type: ignore[arg-type]
            windows_port=windows_port,  # type: ignore[arg-type]
            payload_build_port=payload_build_port,  # type: ignore[arg-type]
            protocol_probe_port=protocol_probe_port,  # type: ignore[arg-type]
            interop_win_port=interop_win_port,  # type: ignore[arg-type]
            interop_lin_port=interop_lin_port,  # type: ignore[arg-type]
            stress_demon_port=stress_demon_port,  # type: ignore[arg-type]
            stress_phantom_port=stress_phantom_port,  # type: ignore[arg-type]
            rbac_admin_port=rbac_admin_port,  # type: ignore[arg-type]
            rbac_viewer_port=rbac_viewer_port,  # type: ignore[arg-type]
            smb_pipe=smb_pipe,  # type: ignore[arg-type]
        ),
        agents=AgentsConfig(available=available_list),
        teamserver=teamserver_obj,
        analyst_operator=analyst_obj,
        archon=archon_obj,
        linux=linux_env_obj,
        kerberos=kerberos_obj,
    )


def validate_env_dict(raw: dict[str, Any]) -> None:
    """Validate *raw* loaded from ``env.toml``; raise :class:`ConfigError` on failure."""
    parse_env_config(raw)


def _parse_target_section(
    name: str,
    d: dict[str, Any],
    errors: list[str],
    *,
    display_optional: bool = True,
) -> TargetSectionConfig | None:
    label = f"[{name}]"
    _unknown_keys(d, _ALLOWED_TARGET_KEYS, label, errors)
    for req in ("host", "user", "work_dir", "key"):
        if req not in d:
            errors.append(f"{label}: missing required key {req!r}")
    host = _non_empty_str(d.get("host"), f"{label}.host", errors)
    port = _require_int(d.get("port", 22), f"{label}.port", errors)
    user = _non_empty_str(d.get("user"), f"{label}.user", errors)
    work_dir = _non_empty_str(d.get("work_dir"), f"{label}.work_dir", errors)
    key = _non_empty_str(d.get("key"), f"{label}.key", errors)
    disp_raw = d.get("display") if display_optional else None
    display: str | None = None
    if disp_raw is not None:
        if not isinstance(disp_raw, str):
            errors.append(f"{label}.display: expected string, got {type(disp_raw).__name__}")
        else:
            display = disp_raw
    if host is None or port is None or user is None or work_dir is None or key is None:
        return None
    return TargetSectionConfig(
        host=host, port=port, user=user, work_dir=work_dir, key=key, display=display
    )


def parse_targets_config(raw: dict[str, Any]) -> TargetsConfig:
    """Parse and validate *raw* targets dict (non-empty ``targets.toml``).

    Raises:
        ConfigError: On unknown stanzas/keys or invalid types.
    """
    errors: list[str] = []

    for k in raw:
        if k not in _ALLOWED_TARGET_STANZAS:
            errors.append(f"unknown top-level key in targets.toml: {k!r}")

    linux = windows = windows2 = None
    if "linux" in raw:
        lt = raw["linux"]
        if isinstance(lt, dict):
            linux = _parse_target_section("linux", lt, errors)
        else:
            errors.append(f"[linux] must be a table, got {type(lt).__name__}")

    if "windows" in raw:
        wt = raw["windows"]
        if isinstance(wt, dict):
            windows = _parse_target_section("windows", wt, errors)
        else:
            errors.append(f"[windows] must be a table, got {type(wt).__name__}")

    if "windows2" in raw:
        w2 = raw["windows2"]
        if isinstance(w2, dict):
            windows2 = _parse_target_section("windows2", w2, errors)
        else:
            errors.append(f"[windows2] must be a table, got {type(w2).__name__}")

    if errors:
        raise ConfigError(errors)

    return TargetsConfig(linux=linux, windows=windows, windows2=windows2)


def validate_targets_dict(raw: dict[str, Any]) -> None:
    """Validate *raw* loaded from ``targets.toml`` (typically non-empty)."""
    parse_targets_config(raw)


def load_env(path: Path) -> dict[str, Any]:
    """Load ``env.toml`` from *path* and validate against the schema.

    If *path* does not exist but a sibling ``<name>.example`` template does,
    seed *path* from the template and emit a clear message so the operator
    can fill in host-specific values (notably ``[server].callback_host``).
    Warns after load if ``callback_host`` is unset — agents on remote targets
    cannot check in without it.
    """
    if not path.exists():
        example = path.parent / (path.name + ".example")
        if example.is_file():
            shutil.copyfile(example, path)
            print(f"[INFO] {path} not found — seeded from {example.name}.")
            print(f"       Edit {path} and set [server].callback_host to this machine's IP")
            print("       (derive with: ip route get <target-ip> | grep -oP 'src \\K[0-9.]+').")
        else:
            raise FileNotFoundError(
                f"{path} not found and no {example.name} template to seed from"
            )
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    validate_env_dict(raw)
    server = raw.get("server") if isinstance(raw.get("server"), dict) else {}
    if not server.get("callback_host"):
        print(
            f"[WARN] {path}: [server].callback_host is unset — scenarios that deploy "
            "agents to remote targets (04, 05, 06, 07, 08, 11, 14, 15, 17, 19, 21-24) "
            "will time out at checkin. Set it to this machine's IP as seen from the "
            "target VMs."
        )
    return raw


def load_targets(path: Path) -> dict[str, Any]:
    """Load ``targets.toml`` if it exists; validate when non-empty.

    If the file is missing, returns ``{}`` and prints the usual hint (caller
    may skip deploy scenarios).
    """
    if not path.exists():
        print(f"[WARN] {path} not found — deploy scenarios will be skipped.")
        print(f"       Copy {path.parent / (path.name + '.example')} to {path} and fill in your values.")
        return {}
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    if raw:
        validate_targets_dict(raw)
    return raw


# ── CLI config ──────────────────────────────────────────────────────────────


def _resolve_cli_server(env: dict[str, Any]) -> str:
    server = env.get("server", {})
    if isinstance(server, dict) and server.get("rest_url"):
        return str(server["rest_url"])

    raw = ""
    if isinstance(server, dict):
        raw = str(server.get("url", ""))
    if raw.startswith("wss://"):
        return "https://" + raw[len("wss://") :]
    if raw.startswith("ws://"):
        return "http://" + raw[len("ws://") :]
    return raw


def _resolve_api_key(env: dict[str, Any]) -> str:
    operator = env.get("operator", {})
    if not isinstance(operator, dict):
        raise KeyError("config/env.toml: [operator] must be a table")
    api_key = operator.get("api_key", "")
    if api_key:
        return str(api_key)
    raise KeyError(
        "config/env.toml is missing operator.api_key; "
        "the autotest harness uses static REST API keys, not operator passwords"
    )


def timeouts_to_env_dict(t: TimeoutsConfig) -> dict[str, Any]:
    """Flatten :class:`TimeoutsConfig` into ``env.toml``-style keys for ``ctx.env['timeouts']``."""

    out: dict[str, Any] = {
        "agent_checkin": t.agent_checkin,
        "agent_checkin_secs": t.agent_checkin,
        "command_output": t.command_output,
        "command_output_secs": t.command_output,
        "agent_disconnect": t.agent_disconnect,
        "screenshot_loot": t.screenshot_loot,
        "loot_entry": t.loot_entry,
        "max_cli_subprocess_secs": t.max_cli_subprocess_secs,
        "listener_startup_secs": t.listener_startup,
        "poll_interval_secs": t.poll_interval,
        "ssh_connect_secs": t.ssh_connect,
        "scp_transfer_secs": t.scp_transfer,
        "stress_concurrent_checkin_secs": t.stress_concurrent_checkin,
    }
    if t.resilience_reconnect is not None:
        out["resilience_reconnect"] = t.resilience_reconnect
    if t.resilience_kill_date is not None:
        out["resilience_kill_date"] = t.resilience_kill_date
    if t.working_hours_probe is not None:
        out["working_hours_probe"] = t.working_hours_probe
    return out


def make_cli_config_from_parsed(cfg: EnvConfig, env: dict[str, Any]) -> CliConfig:
    """Build :class:`CliConfig` from an already-parsed :class:`EnvConfig` (avoids double-parse)."""
    t = cfg.timeouts
    return CliConfig(
        server=_resolve_cli_server(env),
        token=_resolve_api_key(env),
        timeout=int(t.command_output),
        max_subprocess_secs=int(t.max_cli_subprocess_secs),
        cert_fingerprint=cfg.server.cert_fingerprint,
    )


def make_cli_config(env: dict[str, Any]) -> CliConfig:
    """Build the CLI wrapper config from env.toml.

    Call :func:`validate_env_dict` on the dict first when loading from disk
    (``load_env`` does this automatically).
    """
    return make_cli_config_from_parsed(parse_env_config(env), env)
