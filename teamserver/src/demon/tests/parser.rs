use crate::dispatch::util::windows_version_label;

const SERVER: u32 = 2; // any value != VER_NT_WORKSTATION (1)
const WS: u32 = crate::dispatch::util::VER_NT_WORKSTATION;

#[test]
fn windows_version_label_win11() {
    assert_eq!(windows_version_label(10, 0, WS, 0, 22_000), "Windows 11");
    assert_eq!(windows_version_label(10, 0, WS, 0, 22_621), "Windows 11");
}

#[test]
fn windows_version_label_win10() {
    assert_eq!(windows_version_label(10, 0, WS, 0, 19_045), "Windows 10");
}

#[test]
fn windows_version_label_win2022() {
    assert_eq!(windows_version_label(10, 0, SERVER, 0, 20_348), "Windows 2022 Server 22H2");
}

#[test]
fn windows_version_label_win2019() {
    assert_eq!(windows_version_label(10, 0, SERVER, 0, 17_763), "Windows 2019 Server");
}

#[test]
fn windows_version_label_win2016() {
    // Any server build that is not 20348 or 17763 maps to 2016
    assert_eq!(windows_version_label(10, 0, SERVER, 0, 14_393), "Windows 2016 Server");
}

#[test]
fn windows_version_label_win81() {
    assert_eq!(windows_version_label(6, 3, WS, 0, 9_600), "Windows 8.1");
}

#[test]
fn windows_version_label_win_server_2012_r2() {
    assert_eq!(windows_version_label(6, 3, SERVER, 0, 9_600), "Windows Server 2012 R2");
}

#[test]
fn windows_version_label_win8() {
    assert_eq!(windows_version_label(6, 2, WS, 0, 9_200), "Windows 8");
}

#[test]
fn windows_version_label_win_server_2012() {
    assert_eq!(windows_version_label(6, 2, SERVER, 0, 9_200), "Windows Server 2012");
}

#[test]
fn windows_version_label_win7() {
    assert_eq!(windows_version_label(6, 1, WS, 0, 7_601), "Windows 7");
}

#[test]
fn windows_version_label_win_server_2008_r2() {
    assert_eq!(windows_version_label(6, 1, SERVER, 0, 7_601), "Windows Server 2008 R2");
}

#[test]
fn windows_version_label_unknown() {
    assert_eq!(windows_version_label(5, 1, WS, 0, 2_600), "Unknown");
}

#[test]
fn windows_version_label_service_pack_suffix() {
    assert_eq!(windows_version_label(6, 1, WS, 1, 7_601), "Windows 7 Service Pack 1");
    assert_eq!(
        windows_version_label(6, 1, SERVER, 2, 7_601),
        "Windows Server 2008 R2 Service Pack 2"
    );
}

#[test]
fn windows_version_label_no_service_pack_when_zero() {
    // service_pack == 0 must not append the suffix
    let label = windows_version_label(6, 1, WS, 0, 7_601);
    assert!(!label.contains("Service Pack"), "unexpected suffix: {label}");
}
