//! Handlers for domain-related `CommandNet` subcommands.
//!
//! Covers: Domain (domain membership check), Computer (computer enumeration),
//! and DcList (domain controller listing).

use super::super::{CallbackParser, CommandDispatchError};

type HandlerResult = Result<(&'static str, String, Option<String>), CommandDispatchError>;

pub(super) fn handle_domain(parser: &mut CallbackParser<'_>) -> HandlerResult {
    let domain = parser.read_string("net domain")?;
    if domain.is_empty() {
        Ok(("Good", "The machine does not seem to be joined to a domain".to_owned(), None))
    } else {
        Ok(("Good", format!("Domain for this Host: {domain}"), None))
    }
}

pub(super) fn handle_computer(parser: &mut CallbackParser<'_>) -> HandlerResult {
    let target = parser.read_utf16("net computer target")?;
    let mut computers = Vec::new();
    while !parser.is_empty() {
        computers.push(parser.read_utf16("net computer name")?);
    }
    let mut output = String::from(" Computer\n ---------\n");
    for name in &computers {
        output.push_str(&format!("  {name}\n"));
    }
    Ok((
        "Info",
        format!("Computers for {target} [{}]: ", computers.len()),
        Some(output.trim_end().to_owned()),
    ))
}

pub(super) fn handle_dc_list(parser: &mut CallbackParser<'_>) -> HandlerResult {
    let target = parser.read_utf16("net dclist target")?;
    let mut controllers = Vec::new();
    while !parser.is_empty() {
        controllers.push(parser.read_utf16("net dc name")?);
    }
    let mut output = String::from(" Domain Controller\n -------------------\n");
    for name in &controllers {
        output.push_str(&format!("  {name}\n"));
    }
    Ok((
        "Info",
        format!("Domain controllers for {target} [{}]: ", controllers.len()),
        Some(output.trim_end().to_owned()),
    ))
}
