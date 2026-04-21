/// Classifies the kind of TLS failure for UI rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsFailureKind {
    /// Regular TLS error (expired, hostname mismatch, etc.)
    CertificateError,
    /// First connection to an unknown server — show TOFU accept prompt.
    UnknownServer,
    /// Server certificate has changed since first trust — show SSH-style warning.
    CertificateChanged {
        /// The previously trusted fingerprint.
        stored_fingerprint: String,
    },
}

/// Details about a TLS connection failure, surfaced to the UI for actionable messaging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFailure {
    /// Actionable, human-readable description of what went wrong.
    pub message: String,
    /// SHA-256 fingerprint (64 lowercase hex chars) of the server's certificate, if captured.
    pub cert_fingerprint: Option<String>,
    /// What kind of failure this is (determines UI rendering).
    pub kind: TlsFailureKind,
}

/// Outcome of a single login dialog render pass.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum LoginAction {
    /// User has not yet submitted.
    Waiting,
    /// User submitted the login form.
    Submit,
    /// User chose to trust a new server's certificate by its fingerprint.
    TrustCertificate(String),
    /// User explicitly accepted a changed certificate (overrides the SSH-style warning).
    AcceptChangedCertificate(String),
}
