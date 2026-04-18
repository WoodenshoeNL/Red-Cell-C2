use super::*;

// ---- ellipsize tests ----

#[test]
fn ellipsize_shorter_than_max() {
    assert_eq!(ellipsize("hello", 10), "hello");
}

#[test]
fn ellipsize_exactly_at_max() {
    assert_eq!(ellipsize("hello", 5), "hello");
}

#[test]
fn ellipsize_longer_than_max() {
    assert_eq!(ellipsize("hello world", 5), "hell...");
}

#[test]
fn ellipsize_max_one() {
    // max_chars=1 means we break at index 0, so empty prefix + "..."
    assert_eq!(ellipsize("hello", 1), "...");
}

#[test]
fn ellipsize_max_zero() {
    assert_eq!(ellipsize("hello", 0), "...");
}

#[test]
fn ellipsize_empty_string() {
    assert_eq!(ellipsize("", 5), "");
}

#[test]
fn ellipsize_multibyte_chars() {
    // "héllo" is 5 chars; max_chars=3 should keep 2 chars + "..."
    assert_eq!(ellipsize("héllo", 3), "hé...");
}

// ---- blank_if_empty tests ----

#[test]
fn blank_if_empty_returns_value_when_non_empty() {
    assert_eq!(blank_if_empty("hello", "fallback"), "hello");
}

#[test]
fn blank_if_empty_returns_fallback_for_empty_string() {
    assert_eq!(blank_if_empty("", "fallback"), "fallback");
}

#[test]
fn blank_if_empty_returns_fallback_for_whitespace() {
    assert_eq!(blank_if_empty("   ", "fallback"), "fallback");
}

#[test]
fn blank_if_empty_returns_fallback_for_tab_and_newline() {
    assert_eq!(blank_if_empty("\t\n", "fallback"), "fallback");
}

// ---- console_completion_candidates tests ----

#[test]
fn completion_empty_prefix_returns_all_commands() {
    let all = console_completion_candidates("");
    assert_eq!(all.len(), CONSOLE_COMMANDS.len());
    for spec in &CONSOLE_COMMANDS {
        assert!(all.contains(&spec.name), "missing command: {}", spec.name);
    }
}

#[test]
fn completion_prefix_matches_command_names() {
    let matches = console_completion_candidates("sc");
    assert_eq!(matches, vec!["screenshot"]);
}

#[test]
fn completion_prefix_matches_via_alias() {
    // "exit" is an alias for "kill"
    let matches = console_completion_candidates("ex");
    assert!(matches.contains(&"kill"), "expected 'kill' via alias 'exit'");
}

#[test]
fn completion_no_match_returns_empty() {
    let matches = console_completion_candidates("zzz");
    assert!(matches.is_empty());
}

#[test]
fn completion_case_insensitive() {
    let matches = console_completion_candidates("SC");
    assert_eq!(matches, vec!["screenshot"]);
}

#[test]
fn completion_whitespace_only_prefix_returns_all() {
    let all = console_completion_candidates("   ");
    assert_eq!(all.len(), CONSOLE_COMMANDS.len());
}

// ---- closest_command_usage tests ----

#[test]
fn closest_usage_known_command() {
    assert_eq!(closest_command_usage("kill"), Some("kill [process]"));
}

#[test]
fn closest_usage_via_alias() {
    // "exit" is an alias for "kill", should return kill's usage
    assert_eq!(closest_command_usage("exit"), Some("kill [process]"));
}

#[test]
fn closest_usage_unknown_returns_none() {
    assert_eq!(closest_command_usage("nonexistent"), None);
}

#[test]
fn closest_usage_empty_string_returns_none() {
    assert_eq!(closest_command_usage(""), None);
}

// ---- script_status_label ----

#[test]
fn script_status_label_loaded() {
    assert_eq!(script_status_label(ScriptLoadStatus::Loaded), "loaded");
}

#[test]
fn script_status_label_error() {
    assert_eq!(script_status_label(ScriptLoadStatus::Error), "error");
}

#[test]
fn script_status_label_unloaded() {
    assert_eq!(script_status_label(ScriptLoadStatus::Unloaded), "unloaded");
}

#[test]
fn script_status_label_all_variants_non_empty() {
    for status in [ScriptLoadStatus::Loaded, ScriptLoadStatus::Error, ScriptLoadStatus::Unloaded] {
        assert!(!script_status_label(status).is_empty());
    }
}

// ---- script_status_color ----

#[test]
fn script_status_color_loaded() {
    assert_eq!(script_status_color(ScriptLoadStatus::Loaded), Color32::from_rgb(110, 199, 141));
}

#[test]
fn script_status_color_error() {
    assert_eq!(script_status_color(ScriptLoadStatus::Error), Color32::from_rgb(215, 83, 83));
}

#[test]
fn script_status_color_unloaded() {
    assert_eq!(script_status_color(ScriptLoadStatus::Unloaded), Color32::from_rgb(232, 182, 83));
}

#[test]
fn script_status_color_all_variants_distinct() {
    let colors: Vec<Color32> =
        [ScriptLoadStatus::Loaded, ScriptLoadStatus::Error, ScriptLoadStatus::Unloaded]
            .iter()
            .map(|s| script_status_color(*s))
            .collect();
    assert_ne!(colors[0], colors[1]);
    assert_ne!(colors[1], colors[2]);
    assert_ne!(colors[0], colors[2]);
}

// ---- script_output_label ----

#[test]
fn script_output_label_stdout() {
    assert_eq!(script_output_label(ScriptOutputStream::Stdout), "stdout");
}

#[test]
fn script_output_label_stderr() {
    assert_eq!(script_output_label(ScriptOutputStream::Stderr), "stderr");
}

#[test]
fn script_output_label_all_variants_non_empty() {
    for stream in [ScriptOutputStream::Stdout, ScriptOutputStream::Stderr] {
        assert!(!script_output_label(stream).is_empty());
    }
}

// ---- script_output_color ----

#[test]
fn script_output_color_stdout() {
    assert_eq!(script_output_color(ScriptOutputStream::Stdout), Color32::from_rgb(110, 199, 141));
}

#[test]
fn script_output_color_stderr() {
    assert_eq!(script_output_color(ScriptOutputStream::Stderr), Color32::from_rgb(215, 83, 83));
}

#[test]
fn script_output_color_variants_distinct() {
    assert_ne!(
        script_output_color(ScriptOutputStream::Stdout),
        script_output_color(ScriptOutputStream::Stderr)
    );
}

// ---- script_name_for_display ----

#[test]
fn script_name_for_display_extracts_stem() {
    assert_eq!(
        script_name_for_display(Path::new("/home/user/scripts/recon.py")),
        Some("recon".to_owned())
    );
}

#[test]
fn script_name_for_display_no_extension() {
    assert_eq!(
        script_name_for_display(Path::new("/usr/bin/myscript")),
        Some("myscript".to_owned())
    );
}

#[test]
fn script_name_for_display_just_filename() {
    assert_eq!(script_name_for_display(Path::new("tool.py")), Some("tool".to_owned()));
}

#[test]
fn script_name_for_display_empty_path() {
    assert_eq!(script_name_for_display(Path::new("")), None);
}

#[test]
fn script_name_for_display_root_path() {
    assert_eq!(script_name_for_display(Path::new("/")), None);
}

// ---- role_badge_color ----

#[test]
fn role_badge_color_admin() {
    assert_eq!(role_badge_color(Some("admin")), Color32::from_rgb(220, 80, 60));
}

#[test]
fn role_badge_color_admin_case_insensitive() {
    assert_eq!(role_badge_color(Some("Admin")), Color32::from_rgb(220, 80, 60));
    assert_eq!(role_badge_color(Some("ADMIN")), Color32::from_rgb(220, 80, 60));
}

#[test]
fn role_badge_color_operator() {
    assert_eq!(role_badge_color(Some("operator")), Color32::from_rgb(60, 130, 220));
}

#[test]
fn role_badge_color_readonly_variants() {
    let expected = Color32::from_rgb(100, 180, 100);
    assert_eq!(role_badge_color(Some("readonly")), expected);
    assert_eq!(role_badge_color(Some("read-only")), expected);
    assert_eq!(role_badge_color(Some("analyst")), expected);
}

#[test]
fn role_badge_color_unknown_role() {
    assert_eq!(role_badge_color(Some("superuser")), Color32::from_rgb(140, 140, 140));
}

#[test]
fn role_badge_color_none() {
    assert_eq!(role_badge_color(None), Color32::from_rgb(140, 140, 140));
}

// ---- session_graph_status_color ----

#[test]
fn session_graph_status_color_active_variants() {
    let active_color = Color32::from_rgb(84, 170, 110);
    assert_eq!(session_graph_status_color("active"), active_color);
    assert_eq!(session_graph_status_color("alive"), active_color);
    assert_eq!(session_graph_status_color("online"), active_color);
    assert_eq!(session_graph_status_color("true"), active_color);
}

#[test]
fn session_graph_status_color_active_case_insensitive() {
    let active_color = Color32::from_rgb(84, 170, 110);
    assert_eq!(session_graph_status_color("Active"), active_color);
    assert_eq!(session_graph_status_color("ALIVE"), active_color);
}

#[test]
fn session_graph_status_color_dead() {
    let dead_color = Color32::from_rgb(174, 68, 68);
    assert_eq!(session_graph_status_color("dead"), dead_color);
    assert_eq!(session_graph_status_color("offline"), dead_color);
}

#[test]
fn session_graph_status_color_unknown() {
    assert_eq!(session_graph_status_color("something_else"), Color32::from_rgb(174, 68, 68));
}
