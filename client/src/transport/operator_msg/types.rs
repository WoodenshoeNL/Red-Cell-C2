use serde::Deserialize;

use super::super::event_bus::FileBrowserEntry;

#[derive(Debug, Deserialize)]
pub(super) struct FileBrowserSnapshotPayload {
    #[serde(rename = "Path")]
    pub(super) path: String,
    #[serde(rename = "Files", default)]
    pub(super) files: Vec<FileBrowserSnapshotRow>,
}

#[derive(Debug, Deserialize)]
pub(super) struct FileBrowserSnapshotRow {
    #[serde(rename = "Type", default)]
    pub(super) entry_type: String,
    #[serde(rename = "Size", default)]
    pub(super) size: String,
    #[serde(rename = "Modified", default)]
    pub(super) modified: String,
    #[serde(rename = "Name", default)]
    pub(super) name: String,
    #[serde(rename = "Permissions", default)]
    pub(super) permissions: String,
}

pub(super) struct FileBrowserSnapshot {
    pub(super) path: String,
    pub(super) entries: Vec<FileBrowserEntry>,
}
