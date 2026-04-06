use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

use base64::Engine;
use red_cell_common::OperatorInfo;
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{
    AgentResponseInfo, ChatUserInfo, FlatInfo, ListenerInfo, ListenerMarkInfo, Message,
    OperatorMessage,
};
use serde::Deserialize;
use tracing::warn;

use super::event_bus::{
    AgentConsoleEntry, AgentConsoleEntryKind, AgentSummary, AppEvent, AppState, BuildConsoleEntry,
    CompletedDownload, ConnectedOperatorState, ConnectionStatus, DownloadProgress, EventKind,
    FileBrowserEntry, ListenerSummary, LootItem, LootKind, MAX_LOOT_AGENT_ID_CHARS,
    MAX_LOOT_NAME_CHARS, MAX_LOOT_PATH_CHARS, MAX_LOOT_PREVIEW_CHARS, MAX_LOOT_SOURCE_CHARS,
    MAX_LOOT_TIMESTAMP_CHARS, MAX_OPERATOR_ACTIVITY, OperatorActivityEntry, PayloadBuildResult,
    ProcessEntry,
};

impl AppState {
    pub(crate) fn apply_operator_message(&mut self, message: OperatorMessage) -> Vec<AppEvent> {
        let mut events = Vec::new();
        match message {
            OperatorMessage::InitConnectionSuccess(message) => {
                self.connection_status = ConnectionStatus::Connected;
                self.session_start = Some(Instant::now());
                if !message.head.user.is_empty() {
                    self.online_operators.insert(message.head.user.clone());
                    self.operator_info = Some(OperatorInfo {
                        username: message.head.user.clone(),
                        password_hash: None,
                        role: None,
                        online: true,
                        last_seen: Some(message.head.timestamp.clone()),
                    });
                }
                self.push_event(
                    EventKind::System,
                    "teamserver",
                    message.head.timestamp,
                    sanitize_text(&message.info.message),
                );
            }
            OperatorMessage::InitConnectionError(message) => {
                self.last_auth_error = Some(message.info.message.clone());
                self.connection_status = ConnectionStatus::Error(message.info.message.clone());
                self.push_event(
                    EventKind::System,
                    "teamserver",
                    message.head.timestamp,
                    message.info.message,
                );
            }
            OperatorMessage::InitConnectionInfo(message) => {
                self.handle_operator_snapshot(message.info);
            }
            OperatorMessage::ListenerNew(message) => {
                let name = message.info.name.clone().unwrap_or_default();
                self.upsert_listener(listener_summary_from_info(&message.info));
                events.push(AppEvent::ListenerChanged { name, action: "start".to_owned() });
            }
            OperatorMessage::ListenerEdit(message) => {
                let name = message.info.name.clone().unwrap_or_default();
                self.upsert_listener(listener_summary_from_info(&message.info));
                events.push(AppEvent::ListenerChanged { name, action: "edit".to_owned() });
            }
            OperatorMessage::ListenerRemove(message) => {
                let name = message.info.name.clone();
                self.listeners.retain(|listener| listener.name != message.info.name);
                events.push(AppEvent::ListenerChanged { name, action: "stop".to_owned() });
            }
            OperatorMessage::ListenerMark(message) => {
                self.mark_listener(&message.info);
            }
            OperatorMessage::ListenerError(message) => {
                self.upsert_listener(ListenerSummary {
                    name: message.info.name.clone(),
                    protocol: "unknown".to_owned(),
                    host: String::new(),
                    port_bind: String::new(),
                    port_conn: String::new(),
                    status: format!("Error: {}", message.info.error),
                });
                self.push_event(
                    EventKind::System,
                    "teamserver",
                    message.head.timestamp,
                    message.info.error,
                );
            }
            OperatorMessage::ChatMessage(message) => {
                self.push_event(
                    EventKind::Operator,
                    flat_info_string(&message.info, &["User", "Name", "DemonID"])
                        .unwrap_or_else(|| "system".to_owned()),
                    message.head.timestamp,
                    flat_info_string(&message.info, &["Message", "Text", "Output"])
                        .unwrap_or_else(|| "Received event".to_owned()),
                );
            }
            OperatorMessage::ChatListener(message) | OperatorMessage::ChatAgent(message) => {
                self.push_event(
                    EventKind::Agent,
                    flat_info_string(&message.info, &["User", "Name", "DemonID"])
                        .unwrap_or_else(|| "system".to_owned()),
                    message.head.timestamp,
                    flat_info_string(&message.info, &["Message", "Text", "Output"])
                        .unwrap_or_else(|| "Received event".to_owned()),
                );
            }
            OperatorMessage::ChatUserConnected(message) => {
                self.handle_chat_user_presence(message.info, true, message.head.timestamp);
            }
            OperatorMessage::ChatUserDisconnected(message) => {
                self.handle_chat_user_presence(message.info, false, message.head.timestamp);
            }
            OperatorMessage::CredentialsAdd(message)
            | OperatorMessage::CredentialsEdit(message) => {
                if let Some(item) = loot_item_from_flat_info(&message.info, LootKind::Credential) {
                    self.upsert_loot(item.clone());
                    events.push(AppEvent::LootCaptured(item));
                }
            }
            OperatorMessage::CredentialsRemove(message) => {
                self.remove_loot_matching(&message.info, LootKind::Credential);
            }
            OperatorMessage::HostFileAdd(message) => {
                if let Some(item) = loot_item_from_flat_info(&message.info, LootKind::File) {
                    self.upsert_loot(item.clone());
                    events.push(AppEvent::LootCaptured(item));
                }
            }
            OperatorMessage::HostFileRemove(message) => {
                self.remove_loot_matching(&message.info, LootKind::File);
            }
            OperatorMessage::AgentNew(message) => {
                let agent_id = normalize_agent_id(&message.info.name_id);
                self.push_event(
                    EventKind::Agent,
                    "teamserver",
                    message.head.timestamp,
                    format!("Agent {} checked in (new)", agent_id),
                );
                events.push(AppEvent::AgentCheckin(agent_id));
                self.upsert_agent(agent_summary_from_message(&message.info));
            }
            OperatorMessage::AgentReregistered(message) => {
                let agent_id = normalize_agent_id(&message.info.name_id);
                self.push_event(
                    EventKind::Agent,
                    "teamserver",
                    message.head.timestamp,
                    format!("Agent {} re-registered", agent_id),
                );
                events.push(AppEvent::AgentCheckin(agent_id));
                self.upsert_agent(agent_summary_from_message(&message.info));
            }
            OperatorMessage::AgentRemove(message) => {
                if let Some(agent_id) = flat_info_string(&message.info, &["AgentID", "DemonID"]) {
                    self.agents.retain(|agent| agent.name_id != normalize_agent_id(&agent_id));
                }
            }
            OperatorMessage::AgentUpdate(message) => {
                let agent_id = normalize_agent_id(&message.info.agent_id);
                events.push(AppEvent::AgentCheckin(agent_id.clone()));
                if let Some(agent) = self.agents.iter_mut().find(|agent| agent.name_id == agent_id)
                {
                    agent.status = message.info.marked;
                    agent.last_call_in = message.head.timestamp;
                } else {
                    self.agents.push(AgentSummary {
                        name_id: agent_id,
                        status: message.info.marked,
                        domain_name: String::new(),
                        username: String::new(),
                        internal_ip: String::new(),
                        external_ip: String::new(),
                        hostname: String::new(),
                        process_arch: String::new(),
                        process_name: String::new(),
                        process_pid: String::new(),
                        elevated: false,
                        os_version: String::new(),
                        os_build: String::new(),
                        os_arch: String::new(),
                        sleep_delay: String::new(),
                        sleep_jitter: String::new(),
                        last_call_in: message.head.timestamp,
                        note: String::new(),
                        pivot_parent: None,
                        pivot_links: Vec::new(),
                    });
                }
            }
            OperatorMessage::AgentResponse(message) => {
                events.extend(self.handle_agent_response(message));
            }
            OperatorMessage::TeamserverLog(message) => {
                self.push_event(
                    EventKind::System,
                    "teamserver",
                    message.head.timestamp,
                    message.info.text,
                );
            }
            OperatorMessage::BuildPayloadMessage(message) => {
                self.push_event(
                    EventKind::System,
                    "builder",
                    message.head.timestamp,
                    format!("{}: {}", message.info.message_type, message.info.message),
                );
                self.build_console_messages.push(BuildConsoleEntry {
                    message_type: message.info.message_type,
                    message: message.info.message,
                });
            }
            OperatorMessage::BuildPayloadResponse(message) => {
                self.push_event(
                    EventKind::System,
                    "builder",
                    message.head.timestamp.clone(),
                    format!("Built {}", message.info.file_name),
                );
                if let Ok(bytes) =
                    base64::engine::general_purpose::STANDARD.decode(&message.info.payload_array)
                {
                    self.last_payload_response = Some(PayloadBuildResult {
                        payload_bytes: bytes,
                        format: message.info.format,
                        file_name: message.info.file_name,
                    });
                }
            }
            OperatorMessage::AgentTask(message) => {
                self.record_operator_activity(
                    &message.head.user,
                    message.head.timestamp,
                    normalize_agent_id(&message.info.demon_id),
                    message.info.command_line,
                );
            }
            OperatorMessage::Login(_)
            | OperatorMessage::InitConnectionProfile(_)
            | OperatorMessage::BuildPayloadStaged(_)
            | OperatorMessage::BuildPayloadRequest(_)
            | OperatorMessage::BuildPayloadMsOffice(_)
            | OperatorMessage::ServiceAgentRegister(_)
            | OperatorMessage::ServiceListenerRegister(_)
            | OperatorMessage::TeamserverProfile(_) => {}
        }
        events
    }

    fn push_event(
        &mut self,
        kind: EventKind,
        author: impl Into<String>,
        sent_at: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.event_log.push(kind, author, sent_at, message);
    }

    fn upsert_agent(&mut self, agent: AgentSummary) {
        match self.agents.iter_mut().find(|existing| existing.name_id == agent.name_id) {
            Some(existing) => *existing = agent,
            None => self.agents.push(agent),
        }
    }

    pub(crate) fn update_agent_note(&mut self, agent_id: &str, note: String) {
        if let Some(agent) = self.agents.iter_mut().find(|agent| agent.name_id == agent_id) {
            agent.note = note;
        }
    }

    fn upsert_listener(&mut self, listener: ListenerSummary) {
        match self.listeners.iter_mut().find(|existing| existing.name == listener.name) {
            Some(existing) => *existing = listener,
            None => self.listeners.push(listener),
        }
    }

    fn mark_listener(&mut self, mark: &ListenerMarkInfo) {
        let status = mark.mark.clone();
        match self.listeners.iter_mut().find(|listener| listener.name == mark.name) {
            Some(listener) => listener.status = status,
            None => self.listeners.push(ListenerSummary {
                name: mark.name.clone(),
                protocol: "unknown".to_owned(),
                host: String::new(),
                port_bind: String::new(),
                port_conn: String::new(),
                status,
            }),
        }
    }

    fn handle_chat_user_presence(
        &mut self,
        chat_user: ChatUserInfo,
        online: bool,
        timestamp: String,
    ) {
        let action = if online { "connected" } else { "disconnected" };
        if online {
            self.online_operators.insert(chat_user.user.clone());
        } else {
            self.online_operators.remove(&chat_user.user);
        }
        self.push_event(
            EventKind::System,
            "teamserver",
            timestamp.clone(),
            format!("{} {}", chat_user.user, action),
        );

        // Update connected_operators presence state.
        let entry = self.connected_operators.entry(chat_user.user.clone()).or_insert_with(|| {
            ConnectedOperatorState {
                role: None,
                online,
                last_seen: Some(timestamp.clone()),
                recent_commands: VecDeque::new(),
            }
        });
        entry.online = online;
        entry.last_seen = Some(timestamp.clone());

        match &mut self.operator_info {
            Some(operator) if operator.username == chat_user.user => {
                operator.online = online;
                operator.last_seen = Some(timestamp);
            }
            _ if online => {
                self.operator_info = Some(OperatorInfo {
                    username: chat_user.user,
                    password_hash: None,
                    role: None,
                    online,
                    last_seen: Some(timestamp),
                });
            }
            _ => {}
        }
    }

    fn handle_operator_snapshot(&mut self, info: FlatInfo) {
        let Some(operators) = info.fields.get("Operators").cloned() else {
            return;
        };

        let Ok(operators) = serde_json::from_value::<Vec<OperatorInfo>>(operators) else {
            return;
        };

        self.online_operators = operators
            .iter()
            .filter(|operator| operator.online)
            .map(|operator| operator.username.clone())
            .collect();

        // Merge snapshot data into connected_operators, preserving existing activity entries.
        for op in &operators {
            let entry = self.connected_operators.entry(op.username.clone()).or_insert_with(|| {
                ConnectedOperatorState {
                    role: op.role.clone(),
                    online: op.online,
                    last_seen: op.last_seen.clone(),
                    recent_commands: VecDeque::new(),
                }
            });
            entry.role = op.role.clone();
            entry.online = op.online;
            if op.last_seen.is_some() {
                entry.last_seen = op.last_seen.clone();
            }
        }

        if let Some(current_username) =
            self.operator_info.as_ref().map(|info| info.username.clone())
        {
            if let Some(snapshot) =
                operators.into_iter().find(|operator| operator.username == current_username)
            {
                self.operator_info = Some(snapshot);
            }
        }
    }

    /// Records a command dispatch into the operator's activity feed.
    fn record_operator_activity(
        &mut self,
        username: &str,
        timestamp: String,
        agent_id: String,
        command_line: String,
    ) {
        if username.is_empty() {
            return;
        }
        let entry = self.connected_operators.entry(username.to_owned()).or_insert_with(|| {
            ConnectedOperatorState {
                role: None,
                online: true,
                last_seen: Some(timestamp.clone()),
                recent_commands: VecDeque::new(),
            }
        });
        entry.last_seen = Some(timestamp.clone());
        entry.recent_commands.push_front(OperatorActivityEntry {
            timestamp,
            agent_id,
            command_line,
        });
        if entry.recent_commands.len() > MAX_OPERATOR_ACTIVITY {
            entry.recent_commands.pop_back();
        }
    }

    fn handle_agent_response(&mut self, message: Message<AgentResponseInfo>) -> Vec<AppEvent> {
        let agent_id = normalize_agent_id(&message.info.demon_id);
        let mut events = Vec::new();
        self.update_file_browser_state(&agent_id, &message.info);
        self.update_process_list_state(&agent_id, &message);

        if response_is_loot_notification(&message.info) {
            if let Some(loot_item) = loot_item_from_response(&message.info) {
                self.upsert_loot(loot_item.clone());
                events.push(AppEvent::LootCaptured(loot_item));
            }
            return events;
        }

        let output = sanitize_output(&message.info.output);
        if output.is_empty() {
            return events;
        }

        let task_id = extra_string(&message.info.extra, "TaskID").unwrap_or_default();
        if !task_id.is_empty() {
            events.push(AppEvent::AgentTaskResult {
                task_id: task_id.clone(),
                agent_id: agent_id.clone(),
                output: output.clone(),
            });
        }
        events.push(AppEvent::CommandResponse {
            agent_id: agent_id.clone(),
            task_id: task_id.clone(),
            output: output.clone(),
        });

        self.agent_consoles.entry(agent_id).or_default().push(AgentConsoleEntry {
            kind: AgentConsoleEntryKind::from_command_id(&message.info.command_id),
            command_line: message.info.command_line,
            command_id: message.info.command_id,
            task_id,
            received_at: message.head.timestamp,
            output,
        });
        events
    }

    fn update_process_list_state(&mut self, agent_id: &str, message: &Message<AgentResponseInfo>) {
        if message.info.command_id != u32::from(DemonCommand::CommandProcList).to_string() {
            return;
        }

        let Some(rows) = process_list_rows_from_response(&message.info) else {
            return;
        };

        let process_list = self.process_lists.entry(agent_id.to_owned()).or_default();
        process_list.rows = rows;
        process_list.updated_at = Some(message.head.timestamp.clone());
        process_list.status_message = Some(format!(
            "Loaded {} process{}",
            process_list.rows.len(),
            if process_list.rows.len() == 1 { "" } else { "es" }
        ));
    }

    fn upsert_loot(&mut self, loot_item: LootItem) {
        match self.loot.iter_mut().find(|existing| {
            existing.kind == loot_item.kind
                && existing.agent_id == loot_item.agent_id
                && existing.name == loot_item.name
                && existing.collected_at == loot_item.collected_at
        }) {
            Some(existing) => *existing = loot_item,
            None => self.loot.push(loot_item),
        }
        self.loot_revision = self.loot_revision.wrapping_add(1);
    }

    fn remove_loot_matching(&mut self, info: &FlatInfo, fallback_kind: LootKind) {
        if let Some(item) = loot_item_from_flat_info(info, fallback_kind) {
            let initial_len = self.loot.len();
            self.loot.retain(|existing| {
                !(existing.kind == item.kind
                    && existing.agent_id == item.agent_id
                    && existing.name == item.name)
            });
            if self.loot.len() != initial_len {
                self.loot_revision = self.loot_revision.wrapping_add(1);
            }
        }
    }

    fn update_file_browser_state(&mut self, agent_id: &str, info: &AgentResponseInfo) {
        let browser = self.file_browsers.entry(agent_id.to_owned()).or_default();

        if let Some(misc_type) = extra_string(&info.extra, "MiscType") {
            match misc_type.as_str() {
                "FileExplorer" => {
                    if let Some(snapshot) = file_browser_snapshot_from_response(info) {
                        browser.current_dir = Some(snapshot.path.clone());
                        browser.directories.insert(snapshot.path.clone(), snapshot.entries);
                        browser.status_message = Some("Directory listing completed".to_owned());
                    }
                }
                "download-progress" => {
                    if let Some(progress) = download_progress_from_response(info) {
                        if progress.state.eq_ignore_ascii_case("Removed") {
                            browser.downloads.remove(&progress.file_id);
                        } else {
                            browser.downloads.insert(progress.file_id.clone(), progress);
                        }
                    }
                }
                "download" => {
                    if let Some(file_id) = extra_string(&info.extra, "FileID") {
                        browser.downloads.remove(&file_id);
                        // Capture completed download data for the save-to-disk dialog.
                        if let Some(encoded) = extra_string(&info.extra, "MiscData") {
                            if let Ok(data) =
                                base64::engine::general_purpose::STANDARD.decode(encoded.trim())
                            {
                                let remote_path =
                                    extra_string(&info.extra, "FileName").unwrap_or_default();
                                browser
                                    .completed_downloads
                                    .insert(file_id, CompletedDownload { remote_path, data });
                            }
                        }
                    }
                }
                "loot-new" => {
                    if let Some(file_id) = extra_string(&info.extra, "FileID") {
                        browser.downloads.remove(&file_id);
                    }
                }
                _ => {}
            }
        }

        if info.command_id != u32::from(DemonCommand::CommandFs).to_string() {
            return;
        }

        let output = sanitize_output(&info.output);
        if output.is_empty() {
            return;
        }

        if let Some(path) = output.strip_prefix("Current directory: ") {
            browser.current_dir = Some(path.trim().to_owned());
            browser.status_message = Some(output);
        } else if let Some(path) = output.strip_prefix("Changed directory: ") {
            browser.current_dir = Some(path.trim().to_owned());
            browser.status_message = Some(output);
        } else if output.starts_with("Created directory: ")
            || output.starts_with("Removed ")
            || output.starts_with("Uploaded file: ")
            || output.starts_with("Failed to read file: ")
        {
            browser.status_message = Some(output);
        }
    }
}

pub(super) fn listener_summary_from_info(info: &ListenerInfo) -> ListenerSummary {
    ListenerSummary {
        name: info.name.clone().unwrap_or_else(|| "unnamed".to_owned()),
        protocol: info.protocol.clone().unwrap_or_else(|| "unknown".to_owned()),
        host: info.host_bind.clone().unwrap_or_default(),
        port_bind: info.port_bind.clone().unwrap_or_default(),
        port_conn: info.port_conn.clone().unwrap_or_default(),
        status: info.status.clone().unwrap_or_else(|| "Unknown".to_owned()),
    }
}

pub(super) fn agent_summary_from_message(
    info: &red_cell_common::operator::AgentInfo,
) -> AgentSummary {
    let pivot_parent = info
        .pivots
        .parent
        .as_deref()
        .filter(|parent| !parent.trim().is_empty())
        .or_else(|| (!info.pivot_parent.trim().is_empty()).then_some(info.pivot_parent.as_str()))
        .map(normalize_agent_id);
    let pivot_links = info
        .pivots
        .links
        .iter()
        .filter(|link| !link.trim().is_empty())
        .map(|link| normalize_agent_id(link))
        .collect();

    AgentSummary {
        name_id: normalize_agent_id(&info.name_id),
        status: if info.active.eq_ignore_ascii_case("true") {
            "Alive".to_owned()
        } else {
            info.active.clone()
        },
        domain_name: info.domain_name.clone(),
        username: info.username.clone(),
        internal_ip: info.internal_ip.clone(),
        external_ip: info.external_ip.clone(),
        hostname: info.hostname.clone(),
        process_arch: info.process_arch.clone(),
        process_name: info.process_name.clone(),
        process_pid: info.process_pid.clone(),
        elevated: info.elevated,
        os_version: info.os_version.clone(),
        os_build: info.os_build.clone(),
        os_arch: info.os_arch.clone(),
        sleep_delay: info.sleep_delay.to_string(),
        sleep_jitter: info.sleep_jitter.to_string(),
        last_call_in: info.last_call_in.clone(),
        note: info.note.clone(),
        pivot_parent,
        pivot_links,
    }
}

pub(super) fn normalize_agent_id(agent_id: &str) -> String {
    let trimmed = agent_id.trim();
    let without_prefix = trimmed.strip_prefix("0x").unwrap_or(trimmed);

    if let Ok(value) = u32::from_str_radix(without_prefix, 16) {
        return format!("{value:08X}");
    }

    trimmed.to_ascii_uppercase()
}

pub(super) fn flat_info_string(info: &FlatInfo, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        info.fields.get(*key).and_then(|value| match value {
            serde_json::Value::String(string) => Some(string.clone()),
            serde_json::Value::Number(number) => Some(number.to_string()),
            _ => None,
        })
    })
}

pub(super) fn sanitize_text(message: &str) -> String {
    let trimmed = message.trim();
    if trimmed.is_empty() { "Connected".to_owned() } else { trimmed.to_owned() }
}

fn sanitize_output(output: &str) -> String {
    output.trim().to_owned()
}

fn response_is_loot_notification(info: &red_cell_common::operator::AgentResponseInfo) -> bool {
    matches!(
        info.extra.get("MiscType"),
        Some(serde_json::Value::String(kind)) if kind == "loot-new"
    )
}

pub(super) fn loot_item_from_response(
    info: &red_cell_common::operator::AgentResponseInfo,
) -> Option<LootItem> {
    let normalized_agent_id = normalize_agent_id(&info.demon_id);
    let trusted_agent_id = sanitize_loot_required_field(
        normalized_agent_id.as_str(),
        "agent_id",
        normalized_agent_id.clone(),
        MAX_LOOT_AGENT_ID_CHARS,
    )?;
    let name = sanitize_loot_required_field(
        trusted_agent_id.as_str(),
        "name",
        extra_string(&info.extra, "LootName")?,
        MAX_LOOT_NAME_CHARS,
    )?;
    let source = extra_string(&info.extra, "LootKind")
        .or_else(|| extra_string(&info.extra, "Operator"))
        .and_then(|value| {
            sanitize_loot_optional_field(
                trusted_agent_id.as_str(),
                "source",
                value,
                MAX_LOOT_SOURCE_CHARS,
            )
        })
        .unwrap_or_else(|| "unknown".to_owned());
    let collected_at = extra_string(&info.extra, "CapturedAt")
        .and_then(|value| {
            sanitize_loot_optional_field(
                trusted_agent_id.as_str(),
                "collected_at",
                value,
                MAX_LOOT_TIMESTAMP_CHARS,
            )
        })
        .unwrap_or_default();
    let file_path = extra_string(&info.extra, "FilePath").and_then(|value| {
        sanitize_loot_optional_field(
            trusted_agent_id.as_str(),
            "file_path",
            value,
            MAX_LOOT_PATH_CHARS,
        )
    });
    let preview = extra_string(&info.extra, "Preview")
        .or_else(|| extra_string(&info.extra, "Message"))
        .and_then(|value| {
            sanitize_loot_optional_field(
                trusted_agent_id.as_str(),
                "preview",
                value,
                MAX_LOOT_PREVIEW_CHARS,
            )
        });
    let kind = loot_kind_from_strings(
        extra_string(&info.extra, "LootKind").as_deref(),
        Some(name.as_str()),
        file_path.as_deref(),
    );

    Some(LootItem {
        id: extra_i64(&info.extra, "LootID"),
        kind,
        name,
        agent_id: trusted_agent_id,
        source,
        collected_at,
        file_path,
        size_bytes: extra_u64(&info.extra, "SizeBytes"),
        content_base64: extra_string(&info.extra, "ContentBase64")
            .or_else(|| extra_string(&info.extra, "Data")),
        preview,
    })
}

fn process_list_rows_from_response(
    info: &red_cell_common::operator::AgentResponseInfo,
) -> Option<Vec<ProcessEntry>> {
    let rows = info.extra.get("ProcessListRows")?.as_array()?;
    Some(
        rows.iter()
            .filter_map(|row| {
                let pid = row.get("PID")?.as_u64()?;
                let ppid = row.get("PPID")?.as_u64()?;
                let session = row.get("Session")?.as_u64()?;
                Some(ProcessEntry {
                    pid: u32::try_from(pid).ok()?,
                    ppid: u32::try_from(ppid).ok()?,
                    name: row.get("Name")?.as_str()?.to_owned(),
                    arch: row.get("Arch")?.as_str()?.to_owned(),
                    user: row.get("User")?.as_str()?.to_owned(),
                    session: u32::try_from(session).ok()?,
                })
            })
            .collect(),
    )
}

pub(super) fn extra_string(
    extra: &BTreeMap<String, serde_json::Value>,
    key: &str,
) -> Option<String> {
    extra.get(key).and_then(|value| match value {
        serde_json::Value::String(string) => Some(string.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        _ => None,
    })
}

fn extra_u64(extra: &BTreeMap<String, serde_json::Value>, key: &str) -> Option<u64> {
    extra.get(key).and_then(|value| match value {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(string) => string.parse::<u64>().ok(),
        _ => None,
    })
}

fn extra_i64(extra: &BTreeMap<String, serde_json::Value>, key: &str) -> Option<i64> {
    extra.get(key).and_then(|value| match value {
        serde_json::Value::Number(number) => number.as_i64(),
        serde_json::Value::String(string) => string.parse::<i64>().ok(),
        _ => None,
    })
}

pub(super) fn loot_item_from_flat_info(
    info: &FlatInfo,
    fallback_kind: LootKind,
) -> Option<LootItem> {
    let agent_id = flat_info_string(info, &["DemonID", "AgentID"])
        .as_deref()
        .map(normalize_agent_id)
        .and_then(|value| {
            sanitize_loot_optional_field("unknown", "agent_id", value, MAX_LOOT_AGENT_ID_CHARS)
        })
        .unwrap_or_default();
    let name = sanitize_loot_required_field(
        agent_id.as_str(),
        "name",
        flat_info_string(info, &["Name", "FileName", "LootName"])?,
        MAX_LOOT_NAME_CHARS,
    )?;
    let file_path = flat_info_string(info, &["FilePath", "Path"]).and_then(|value| {
        sanitize_loot_optional_field(agent_id.as_str(), "file_path", value, MAX_LOOT_PATH_CHARS)
    });
    let source = flat_info_string(info, &["Operator", "Pattern", "Kind", "Type"])
        .and_then(|value| {
            sanitize_loot_optional_field(agent_id.as_str(), "source", value, MAX_LOOT_SOURCE_CHARS)
        })
        .unwrap_or_else(|| fallback_kind.label().to_ascii_lowercase());
    let collected_at = flat_info_string(info, &["CapturedAt", "Time", "Timestamp"])
        .and_then(|value| {
            sanitize_loot_optional_field(
                agent_id.as_str(),
                "collected_at",
                value,
                MAX_LOOT_TIMESTAMP_CHARS,
            )
        })
        .unwrap_or_default();
    let preview = flat_info_string(info, &["Credential", "Preview", "Message"]).and_then(|value| {
        sanitize_loot_optional_field(agent_id.as_str(), "preview", value, MAX_LOOT_PREVIEW_CHARS)
    });
    let kind = loot_kind_from_strings(
        flat_info_string(info, &["Kind", "Type", "LootKind"]).as_deref(),
        Some(name.as_str()),
        file_path.as_deref(),
    );

    Some(LootItem {
        id: flat_info_i64(info, &["LootID", "ID"]),
        kind: if matches!(kind, LootKind::Other) { fallback_kind } else { kind },
        name,
        agent_id,
        source,
        collected_at,
        file_path,
        size_bytes: flat_info_u64(info, &["SizeBytes", "Size"]),
        content_base64: flat_info_string(info, &["ContentBase64", "Data", "Payload"]),
        preview,
    })
}

fn sanitize_loot_required_field(
    agent_id: &str,
    field_name: &'static str,
    value: String,
    max_chars: usize,
) -> Option<String> {
    let sanitized = sanitize_loot_field(agent_id, field_name, value, max_chars);
    if sanitized.is_empty() {
        warn!(
            agent_id = display_agent_id(agent_id),
            loot_field = field_name,
            "dropping loot item with empty required field after sanitization"
        );
        None
    } else {
        Some(sanitized)
    }
}

fn sanitize_loot_optional_field(
    agent_id: &str,
    field_name: &'static str,
    value: String,
    max_chars: usize,
) -> Option<String> {
    let sanitized = sanitize_loot_field(agent_id, field_name, value, max_chars);
    (!sanitized.is_empty()).then_some(sanitized)
}

fn sanitize_loot_field(
    agent_id: &str,
    field_name: &'static str,
    value: String,
    max_chars: usize,
) -> String {
    let original_char_count = value.chars().count();
    let had_control_chars = value.chars().any(char::is_control);
    let cleaned = value
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>()
        .trim()
        .to_owned();
    let cleaned_char_count = cleaned.chars().count();
    let truncated = cleaned_char_count > max_chars;
    let sanitized =
        if truncated { cleaned.chars().take(max_chars).collect::<String>() } else { cleaned };

    if had_control_chars || original_char_count > max_chars {
        warn!(
            agent_id = display_agent_id(agent_id),
            loot_field = field_name,
            original_chars = original_char_count,
            sanitized_chars = sanitized.chars().count(),
            had_control_chars,
            truncated,
            "sanitized suspicious loot field"
        );
    }

    sanitized
}

fn display_agent_id(agent_id: &str) -> &str {
    if agent_id.is_empty() { "unknown" } else { agent_id }
}

fn flat_info_u64(info: &FlatInfo, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        info.fields.get(*key).and_then(|value| match value {
            serde_json::Value::Number(number) => number.as_u64(),
            serde_json::Value::String(string) => string.parse::<u64>().ok(),
            _ => None,
        })
    })
}

fn flat_info_i64(info: &FlatInfo, keys: &[&str]) -> Option<i64> {
    keys.iter().find_map(|key| {
        info.fields.get(*key).and_then(|value| match value {
            serde_json::Value::Number(number) => number.as_i64(),
            serde_json::Value::String(string) => string.parse::<i64>().ok(),
            _ => None,
        })
    })
}

pub(super) fn loot_kind_from_strings(
    kind: Option<&str>,
    name: Option<&str>,
    file_path: Option<&str>,
) -> LootKind {
    let mut haystacks = Vec::new();
    if let Some(kind) = kind {
        haystacks.push(kind.to_ascii_lowercase());
    }
    if let Some(name) = name {
        haystacks.push(name.to_ascii_lowercase());
    }
    if let Some(path) = file_path {
        haystacks.push(path.to_ascii_lowercase());
    }

    if haystacks.iter().any(|value| value.contains("credential") || value.contains("password")) {
        LootKind::Credential
    } else if haystacks.iter().any(|value| {
        value.contains("screenshot")
            || value.ends_with(".png")
            || value.ends_with(".jpg")
            || value.ends_with(".jpeg")
    }) {
        LootKind::Screenshot
    } else if haystacks.iter().any(|value| {
        value.contains("file")
            || value.contains("download")
            || value.contains('\\')
            || value.contains('/')
    }) {
        LootKind::File
    } else {
        LootKind::Other
    }
}

#[derive(Debug, Deserialize)]
struct FileBrowserSnapshotPayload {
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Files", default)]
    files: Vec<FileBrowserSnapshotRow>,
}

#[derive(Debug, Deserialize)]
struct FileBrowserSnapshotRow {
    #[serde(rename = "Type", default)]
    entry_type: String,
    #[serde(rename = "Size", default)]
    size: String,
    #[serde(rename = "Modified", default)]
    modified: String,
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Permissions", default)]
    permissions: String,
}

struct FileBrowserSnapshot {
    path: String,
    entries: Vec<FileBrowserEntry>,
}

fn file_browser_snapshot_from_response(
    info: &red_cell_common::operator::AgentResponseInfo,
) -> Option<FileBrowserSnapshot> {
    let encoded = extra_string(&info.extra, "MiscData")?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
    let payload = serde_json::from_slice::<FileBrowserSnapshotPayload>(&bytes).ok()?;
    let path = payload.path.trim().to_owned();
    if path.is_empty() {
        return None;
    }

    let entries = payload
        .files
        .into_iter()
        .map(|row| {
            let name = row.name.trim().to_owned();
            let path = join_remote_path(&path, &name);
            let size_label = row.size.trim().to_owned();
            FileBrowserEntry {
                name,
                path,
                is_dir: row.entry_type.eq_ignore_ascii_case("dir"),
                size_bytes: parse_human_size(&size_label),
                size_label,
                modified_at: row.modified.trim().to_owned(),
                permissions: row.permissions.trim().to_owned(),
            }
        })
        .collect();

    Some(FileBrowserSnapshot { path, entries })
}

fn download_progress_from_response(
    info: &red_cell_common::operator::AgentResponseInfo,
) -> Option<DownloadProgress> {
    Some(DownloadProgress {
        file_id: extra_string(&info.extra, "FileID")?,
        remote_path: extra_string(&info.extra, "FileName")?,
        current_size: extra_u64(&info.extra, "CurrentSize")?,
        expected_size: extra_u64(&info.extra, "ExpectedSize")?,
        state: extra_string(&info.extra, "State").unwrap_or_else(|| "InProgress".to_owned()),
    })
}

fn join_remote_path(base: &str, name: &str) -> String {
    if base.is_empty() {
        return name.to_owned();
    }
    if name.is_empty() {
        return base.to_owned();
    }

    let separator = if base.contains('\\') { '\\' } else { '/' };
    if base.ends_with(['\\', '/']) {
        format!("{base}{name}")
    } else {
        format!("{base}{separator}{name}")
    }
}

fn parse_human_size(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut parts = trimmed.split_whitespace();
    let number = parts.next()?.parse::<f64>().ok()?;
    let unit = parts.next().unwrap_or("B").to_ascii_uppercase();
    let multiplier = match unit.as_str() {
        "B" => 1_f64,
        "KB" => 1024_f64,
        "MB" => 1024_f64 * 1024_f64,
        "GB" => 1024_f64 * 1024_f64 * 1024_f64,
        _ => return None,
    };

    Some((number * multiplier).round() as u64)
}
