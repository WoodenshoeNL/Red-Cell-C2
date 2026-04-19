use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use base64::Engine;
use red_cell_common::OperatorInfo;
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{
    AgentResponseInfo, ChatUserInfo, FlatInfo, ListenerMarkInfo, Message, OperatorMessage,
};

use super::super::event_bus::{
    AgentConsoleEntry, AgentConsoleEntryKind, AgentSummary, AppEvent, AppState, BuildConsoleEntry,
    CompletedDownload, ConnectedOperatorState, ConnectionStatus, EventKind, ListenerSummary,
    LootItem, LootKind, MAX_OPERATOR_ACTIVITY, OperatorActivityEntry, PayloadBuildResult,
};
use super::serialize::{
    agent_summary_from_message, download_progress_from_response, extra_string,
    file_browser_snapshot_from_response, flat_info_string, listener_summary_from_info,
    loot_item_from_flat_info, loot_item_from_response, normalize_agent_id,
    process_list_rows_from_response, response_is_loot_notification, sanitize_output, sanitize_text,
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
                Arc::make_mut(&mut self.listeners)
                    .retain(|listener| listener.name != message.info.name);
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
                    Arc::make_mut(&mut self.agents)
                        .retain(|agent| agent.name_id != normalize_agent_id(&agent_id));
                }
            }
            OperatorMessage::AgentUpdate(message) => {
                let agent_id = normalize_agent_id(&message.info.agent_id);
                events.push(AppEvent::AgentCheckin(agent_id.clone()));
                let agents = Arc::make_mut(&mut self.agents);
                if let Some(agent) = agents.iter_mut().find(|agent| agent.name_id == agent_id) {
                    agent.status = message.info.marked;
                    agent.last_call_in = message.head.timestamp;
                } else {
                    agents.push(AgentSummary {
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
                Arc::make_mut(&mut self.build_console_messages).push(BuildConsoleEntry {
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
            | OperatorMessage::TeamserverProfile(_)
            | OperatorMessage::DatabaseDegraded(_)
            | OperatorMessage::DatabaseRecovered(_)
            | OperatorMessage::OperatorCreate(_)
            | OperatorMessage::OperatorRemove(_) => {}
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
        let agents = Arc::make_mut(&mut self.agents);
        match agents.iter_mut().find(|existing| existing.name_id == agent.name_id) {
            Some(existing) => *existing = agent,
            None => agents.push(agent),
        }
    }

    pub(crate) fn update_agent_note(&mut self, agent_id: &str, note: String) {
        if let Some(agent) =
            Arc::make_mut(&mut self.agents).iter_mut().find(|agent| agent.name_id == agent_id)
        {
            agent.note = note;
        }
    }

    fn upsert_listener(&mut self, listener: ListenerSummary) {
        let listeners = Arc::make_mut(&mut self.listeners);
        match listeners.iter_mut().find(|existing| existing.name == listener.name) {
            Some(existing) => *existing = listener,
            None => listeners.push(listener),
        }
    }

    fn mark_listener(&mut self, mark: &ListenerMarkInfo) {
        let status = mark.mark.clone();
        let listeners = Arc::make_mut(&mut self.listeners);
        match listeners.iter_mut().find(|listener| listener.name == mark.name) {
            Some(listener) => listener.status = status,
            None => listeners.push(ListenerSummary {
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
        process_list.refresh_generation = process_list.refresh_generation.saturating_add(1);
        process_list.updated_at = Some(message.head.timestamp.clone());
        process_list.status_message = Some(format!(
            "Loaded {} process{}",
            process_list.rows.len(),
            if process_list.rows.len() == 1 { "" } else { "es" }
        ));
    }

    fn upsert_loot(&mut self, loot_item: LootItem) {
        let loot = Arc::make_mut(&mut self.loot);
        match loot.iter_mut().find(|existing| {
            existing.kind == loot_item.kind
                && existing.agent_id == loot_item.agent_id
                && existing.name == loot_item.name
                && existing.collected_at == loot_item.collected_at
        }) {
            Some(existing) => *existing = loot_item,
            None => loot.push(loot_item),
        }
        self.loot_revision = self.loot_revision.wrapping_add(1);
    }

    fn remove_loot_matching(&mut self, info: &FlatInfo, fallback_kind: LootKind) {
        if let Some(item) = loot_item_from_flat_info(info, fallback_kind) {
            let loot = Arc::make_mut(&mut self.loot);
            let initial_len = loot.len();
            loot.retain(|existing| {
                !(existing.kind == item.kind
                    && existing.agent_id == item.agent_id
                    && existing.name == item.name)
            });
            if loot.len() != initial_len {
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
