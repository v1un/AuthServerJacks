// C:/Users/vini/RustroverProjects/AuthServerJacks/src/config.rs
use anyhow::Context;
use once_cell::sync::Lazy;
use std::env;

// JWT_SECRET remains a lazy static, loaded once when first accessed.
pub static JWT_SECRET: Lazy<String> = Lazy::new(|| {
    env::var("JWT_SECRET").expect("JWT_SECRET must be set in environment variables")
});

// Make Config cloneable for Axum state
#[derive(Clone, Debug)] // Added Debug for easier inspection if needed
pub struct Config {
    pub database_url: String,
    pub port: u16,
    pub admin_username: String,
    pub admin_password: String,
    pub jwt_expiry_hours: i64,
}

impl Config {
    // Load configuration from environment variables.
    // This should ideally be called only once at startup.
    pub fn from_env() -> anyhow::Result<Self> {
        // Load DATABASE_URL, default to "sqlite:auth.db"
        let database_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "sqlite:auth.db".to_string());
        tracing::debug!("Using database URL: {}", database_url);

        // Load PORT, default to 3000
        let port = env::var("PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse()
            .context("Failed to parse PORT environment variable")?;
        tracing::debug!("Using port: {}", port);

        // Load ADMIN_USERNAME, required
        let admin_username = env::var("ADMIN_USERNAME")
            .context("ADMIN_USERNAME must be set in environment variables")?;
        // Avoid logging sensitive data like username/password in production
        tracing::debug!("Admin username configured");

        // Load ADMIN_PASSWORD, required
        let admin_password = env::var("ADMIN_PASSWORD")
            .context("ADMIN_PASSWORD must be set in environment variables")?;
        tracing::debug!("Admin password configured (length: {})", admin_password.len()); // Log length, not password


        // Load JWT_EXPIRY_HOURS, default to 24
        let jwt_expiry_hours = env::var("JWT_EXPIRY_HOURS")
            .unwrap_or_else(|_| "24".to_string())
            .parse()
            .context("Failed to parse JWT_EXPIRY_HOURS environment variable")?;
        tracing::debug!("JWT expiry set to {} hours", jwt_expiry_hours);

        // Ensure JWT_SECRET is accessible (this will panic if not set, as intended by Lazy::new)
        // Accessing it here ensures the check happens during config load.
        let _ = &*JWT_SECRET;
        tracing::debug!("JWT_SECRET loaded");

        Ok(Config {
            database_url,
            port,
            admin_username,
            admin_password,
            jwt_expiry_hours,
        })
    }
}