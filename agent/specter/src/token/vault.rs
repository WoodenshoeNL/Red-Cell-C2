//! In-memory token vault for the Specter agent.

use super::TokenEntry;

/// In-memory vault of Windows access tokens.
///
/// Token IDs are 0-based indices into the vault.  When a token is removed, its
/// slot is set to `None` so that existing IDs remain stable.
#[derive(Debug)]
pub struct TokenVault {
    /// Sparse list of tokens (removed entries are `None`).
    tokens: Vec<Option<TokenEntry>>,
    /// Index of the currently impersonated token, if any.
    impersonating: Option<usize>,
}

impl Default for TokenVault {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenVault {
    /// Create an empty vault.
    pub fn new() -> Self {
        Self { tokens: Vec::new(), impersonating: None }
    }

    /// Add a token to the vault and return its ID (0-based index).
    pub fn add(&mut self, entry: TokenEntry) -> u32 {
        // Reuse a removed slot if available.
        for (i, slot) in self.tokens.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(entry);
                #[allow(clippy::cast_possible_truncation)]
                return i as u32;
            }
        }
        let id = self.tokens.len();
        self.tokens.push(Some(entry));
        #[allow(clippy::cast_possible_truncation)]
        (id as u32)
    }

    /// Get a reference to a token by ID.
    pub fn get(&self, id: u32) -> Option<&TokenEntry> {
        self.tokens.get(id as usize).and_then(|s| s.as_ref())
    }

    /// Remove a token by ID.  Returns `true` if the token existed.
    ///
    /// On Windows, callers are responsible for closing the underlying handle
    /// before calling this method.
    pub fn remove(&mut self, id: u32) -> bool {
        let idx = id as usize;
        if idx < self.tokens.len() && self.tokens[idx].is_some() {
            // If we're removing the impersonated token, clear impersonation.
            if self.impersonating == Some(idx) {
                self.impersonating = None;
            }
            self.tokens[idx] = None;
            true
        } else {
            false
        }
    }

    /// Clear all tokens from the vault.
    ///
    /// On Windows, callers are responsible for closing underlying handles first.
    pub fn clear(&mut self) {
        self.tokens.clear();
        self.impersonating = None;
    }

    /// Iterate over all live `(id, entry)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (u32, &TokenEntry)> {
        self.tokens.iter().enumerate().filter_map(|(i, slot)| {
            #[allow(clippy::cast_possible_truncation)]
            slot.as_ref().map(|e| (i as u32, e))
        })
    }

    /// Number of live tokens in the vault.
    pub fn len(&self) -> usize {
        self.tokens.iter().filter(|s| s.is_some()).count()
    }

    /// Whether the vault is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Set the impersonating token index.
    pub fn set_impersonating(&mut self, id: Option<u32>) {
        self.impersonating = id.map(|i| i as usize);
    }

    /// Get the currently impersonated token ID, if any.
    pub fn impersonating(&self) -> Option<u32> {
        #[allow(clippy::cast_possible_truncation)]
        self.impersonating.map(|i| i as u32)
    }

    /// Check whether a given token ID is the currently impersonated token.
    pub fn is_impersonating(&self, id: u32) -> bool {
        self.impersonating == Some(id as usize)
    }
}
