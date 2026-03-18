//! Listener profile trait — defines how a C2 profile shapes paths and headers.

/// A listener profile controls URL paths and request headers for C2 traffic camouflage.
pub trait ListenerProfile: Send + Sync {
    /// Unique profile name (stored in DB, referenced in agent config).
    fn name(&self) -> &str;

    /// Base path prefix prepended to /register, /poll/{id}, /result/{id}.
    /// Return empty string for no prefix.
    fn base_path(&self) -> &str;

    /// Expected User-Agent value, if this profile enforces one.
    fn user_agent(&self) -> Option<&str>;

    /// Validate that an incoming request's path and User-Agent match this profile.
    fn validate(&self, path: &str, user_agent: Option<&str>) -> bool {
        if !self.base_path().is_empty() && !path.starts_with(self.base_path()) {
            return false;
        }
        match self.user_agent() {
            Some(expected) => user_agent == Some(expected),
            None => true,
        }
    }
}

// ─── Built-in profiles ───

/// Default profile: bare /register, /poll, /result paths, no special headers.
pub struct DefaultProfile;

impl ListenerProfile for DefaultProfile {
    fn name(&self) -> &str { "default" }
    fn base_path(&self) -> &str { "" }
    fn user_agent(&self) -> Option<&str> { None }
}

/// Health-check camouflage profile.
pub struct HealthProfile;

impl ListenerProfile for HealthProfile {
    fn name(&self) -> &str { crate::constants::HEALTH_PROFILE_NAME }
    fn base_path(&self) -> &str { crate::constants::HEALTH_BASE_PATH }
    fn user_agent(&self) -> Option<&str> { Some(crate::constants::HEALTH_USER_AGENT) }
}

/// Look up a boxed profile by name. Returns DefaultProfile for unknown names.
pub fn profile_by_name(name: &str) -> Box<dyn ListenerProfile> {
    match name {
        n if n == crate::constants::HEALTH_PROFILE_NAME => Box::new(HealthProfile),
        _ => Box::new(DefaultProfile),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_accepts_any_ua() {
        let p = DefaultProfile;
        assert!(p.validate("/register", None));
        assert!(p.validate("/register", Some("curl/7.0")));
    }

    #[test]
    fn health_profile_requires_path_and_ua() {
        let p = HealthProfile;
        assert!(p.validate("/api/health/metrics/register", Some("HealthMonitor/1.3")));
        assert!(!p.validate("/register", Some("HealthMonitor/1.3")));
        assert!(!p.validate("/api/health/metrics/register", Some("curl/7.0")));
        assert!(!p.validate("/api/health/metrics/register", None));
    }

    #[test]
    fn profile_by_name_lookup() {
        let p = profile_by_name("health_api");
        assert_eq!(p.name(), "health_api");
        let p = profile_by_name("unknown");
        assert_eq!(p.name(), "default");
    }
}
