//! File-browser queue helpers for `ClientApp`.

use rfd::FileDialog;

use crate::ClientApp;
use crate::helpers::join_remote_path;
use crate::tasks::{
    build_file_browser_cd_task, build_file_browser_delete_task, build_file_browser_download_task,
    build_file_browser_pwd_task, build_file_browser_upload_task, build_transfer_stop_task,
};

impl ClientApp {
    pub(crate) fn queue_file_browser_pwd(&mut self, agent_id: &str) {
        let message = build_file_browser_pwd_task(agent_id, &self.current_operator_username());
        self.session_panel.file_browser_state_mut(agent_id).status_message =
            Some("Queued `pwd`.".to_owned());
        self.session_panel.pending_messages.push(message);
    }

    pub(crate) fn queue_file_browser_list(&mut self, agent_id: &str, path: &str) {
        if let Some(message) = self.build_file_browser_list_message(agent_id, path) {
            let ui_state = self.session_panel.file_browser_state_mut(agent_id);
            ui_state.pending_dirs.insert(path.to_owned());
            ui_state.status_message = Some(format!("Queued listing for {path}."));
            self.session_panel.pending_messages.push(message);
        }
    }

    pub(crate) fn queue_file_browser_cd(&mut self, agent_id: &str, path: &str) {
        let message = build_file_browser_cd_task(agent_id, path, &self.current_operator_username());
        self.session_panel.file_browser_state_mut(agent_id).status_message =
            Some(format!("Queued directory change to {path}."));
        self.session_panel.pending_messages.push(message);
    }

    pub(crate) fn queue_file_browser_download(&mut self, agent_id: &str, path: &str) {
        let message =
            build_file_browser_download_task(agent_id, path, &self.current_operator_username());
        self.session_panel.file_browser_state_mut(agent_id).status_message =
            Some(format!("Queued download for {path}."));
        self.session_panel.pending_messages.push(message);
    }

    pub(crate) fn queue_file_browser_delete(&mut self, agent_id: &str, path: &str) {
        let message =
            build_file_browser_delete_task(agent_id, path, &self.current_operator_username());
        self.session_panel.file_browser_state_mut(agent_id).status_message =
            Some(format!("Queued delete for {path}."));
        self.session_panel.pending_messages.push(message);
    }

    pub(crate) fn queue_file_browser_upload(
        &mut self,
        agent_id: &str,
        destination_dir: Option<String>,
    ) {
        let Some(destination_dir) = destination_dir else {
            self.session_panel.file_browser_state_mut(agent_id).status_message = Some(
                "Select a directory or resolve the current working directory first.".to_owned(),
            );
            return;
        };

        let Some(local_path) = FileDialog::new().pick_file() else {
            return;
        };

        match std::fs::read(&local_path) {
            Ok(bytes) => {
                let file_name =
                    local_path.file_name().and_then(|value| value.to_str()).unwrap_or("upload.bin");
                let remote_path = join_remote_path(&destination_dir, file_name);
                let message = build_file_browser_upload_task(
                    agent_id,
                    &remote_path,
                    &bytes,
                    &self.current_operator_username(),
                );
                self.session_panel.file_browser_state_mut(agent_id).status_message =
                    Some(format!("Queued upload to {remote_path}."));
                self.session_panel.pending_messages.push(message);
            }
            Err(error) => {
                self.session_panel.file_browser_state_mut(agent_id).status_message =
                    Some(format!("Failed to read local file: {error}"));
            }
        }
    }

    pub(crate) fn queue_file_browser_download_cancel(&mut self, agent_id: &str, file_id: &str) {
        let operator = self.current_operator_username();
        if let Some(message) = build_transfer_stop_task(agent_id, file_id, &operator) {
            self.session_panel.file_browser_state_mut(agent_id).status_message =
                Some(format!("Queued cancel for download {file_id}."));
            self.session_panel.pending_messages.push(message);
        } else {
            self.session_panel.file_browser_state_mut(agent_id).status_message =
                Some(format!("Could not build cancel message: invalid file ID {file_id}."));
        }
    }
}
