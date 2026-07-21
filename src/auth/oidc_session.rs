use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::time::{Duration, Instant};

const SESSION_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_SESSIONS: usize = 1024;

#[derive(Debug, Clone)]
pub struct OidcSession {
    pub pkce_verifier: String,
    pub nonce: String,
    created_at: Instant,
}

#[derive(Debug)]
pub struct OidcSessionStore {
    sessions: DashMap<String, OidcSession>,
}

pub static OIDC_SESSIONS: Lazy<OidcSessionStore> = Lazy::new(OidcSessionStore::new);

impl OidcSessionStore {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    pub fn insert(&self, state: String, pkce_verifier: String, nonce: String) {
        self.cleanup_expired();
        if self.sessions.len() >= MAX_SESSIONS {
            if let Some(oldest) = self
                .sessions
                .iter()
                .min_by_key(|entry| entry.value().created_at)
                .map(|entry| entry.key().clone())
            {
                self.sessions.remove(&oldest);
            }
        }
        self.sessions.insert(
            state,
            OidcSession {
                pkce_verifier,
                nonce,
                created_at: Instant::now(),
            },
        );
    }

    pub fn take(&self, state: &str) -> Option<OidcSession> {
        self.sessions.remove(state).and_then(|(_, session)| {
            if session.created_at.elapsed() <= SESSION_TTL {
                Some(session)
            } else {
                None
            }
        })
    }

    fn cleanup_expired(&self) {
        let expired: Vec<String> = self
            .sessions
            .iter()
            .filter_map(|entry| {
                if entry.value().created_at.elapsed() > SESSION_TTL {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();
        for key in expired {
            self.sessions.remove(&key);
        }
    }

    #[cfg(test)]
    pub fn insert_expired(&self, state: String, pkce_verifier: String, nonce: String) {
        self.sessions.insert(
            state,
            OidcSession {
                pkce_verifier,
                nonce,
                created_at: Instant::now() - SESSION_TTL - Duration::from_secs(1),
            },
        );
    }
}
