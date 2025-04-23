mod config;
mod db;
mod error;
mod handlers;
mod middleware;
mod models;

// Use anyhow::Context for error handling in main
use anyhow::Context as AnyhowContext;
use crate::config::Config;
use crate::db::{init_db, DbPool}; // Keep DbPool type alias
use crate::handlers::{admin, auth, web};
// Import specific middleware functions and AppError
use crate::middleware::{authenticate, require_admin}; // require_auth is defined but not used in routes below
use crate::error::AppError; // Import AppError for main's Result

use axum::{
    // State is extracted in handlers/middleware, not needed directly in routing definitions
    extract::State,
    http::{header, Method, StatusCode},
    middleware as axum_middleware, // Alias to avoid naming conflict
    routing::{delete, get, post, patch}, // Import patch explicitly
    Router, response::IntoResponse, // Import IntoResponse
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc}; // Import Arc
use tower::ServiceBuilder; // Import ServiceBuilder
use tower_http::{
    cors::{Any, CorsLayer},
    services::ServeDir,
    trace::TraceLayer, // Add TraceLayer for logging requests
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Define the application state
#[derive(Clone)]
pub struct AppState {
    // Make fields public or provide getter methods if needed outside this module
    // For now, they are used internally by handlers via State extractor
    pub db_pool: DbPool,
    pub config: Config,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> { // Use anyhow::Result for top-level errors
    // Load environment variables from .env file if it exists
    dotenvy::dotenv().ok(); // .ok() ignores errors if .env is not found

    // Initialize tracing (logging)
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "auth_server_jacks=info,tower_http=info".into()), // Default level
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting AuthServerJacks...");

    // Load application config ONCE
    let config = Config::from_env().context("Failed to load configuration from environment")?;
    tracing::info!("Configuration loaded successfully");

    // Initialize database connection pool
    // Use context for better error message on failure
    let db_pool = init_db(&config.database_url)
        .await
        .context("Failed to initialize database")?;
    tracing::info!("Database pool initialized successfully");

    // Create the application state
    let app_state = Arc::new(AppState {
        db_pool: db_pool.clone(), // Clone the pool for the state
        config: config.clone(),   // Clone the config for the state
    });

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_origin(Any) // Allow any origin (adjust for production)
        // Ensure all needed methods and headers are allowed
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);
    // Expose headers if needed by frontend (usually not necessary for simple cases)
    // .expose_headers([header::CONTENT_TYPE]);

    // Ensure static and template directories exist
    // Use context for better error messages
    create_dir_if_not_exists("static/css").context("Failed to create static/css directory")?;
    create_dir_if_not_exists("static/js").context("Failed to create static/js directory")?;
    create_dir_if_not_exists("templates").context("Failed to create templates directory")?;

    // --- Define Routes ---

    // API routes requiring admin privileges
    let admin_api_routes = Router::new()        
        .route("/add-user", post(admin::add_user))
        .route("/users", get(admin::list_users))
        .route("/users/:user_id", get(admin::get_user))
        .route("/users/:user_id", patch(admin::update_user)) // Use patch for updates
        .route("/users/:user_id", delete(admin::delete_user))
        // Apply middleware using route_layer. Order matters: bottom layer runs first.
        // 1. Authenticate (verifies token, adds Claims)        
        // 2. Require Admin (checks Claims for admin role)        
        .route_layer(axum_middleware::from_fn_with_state(app_state.clone(), require_admin))
        .route_layer(axum_middleware::from_fn_with_state(app_state.clone(), authenticate));


    // Web UI routes requiring admin privileges
    let admin_web_routes = Router::new()
        .route("/", get(web::admin_dashboard))
        .route("/users", get(web::admin_users_page))
        .route("/add-user", get(web::admin_add_user_page))
        // Apply middleware using route_layer, same order as API        
        .route_layer(axum_middleware::from_fn_with_state(app_state.clone(), require_admin))
        .route_layer(axum_middleware::from_fn_with_state(app_state.clone(), authenticate));

    // Public API routes (no auth required)
    let public_api_routes = Router::new()
        .route("/login", post(auth::login)) // User login
        .route("/admin/login", post(admin::login)); // Admin login

    // Public Web UI routes (no auth required)
    let public_web_routes = Router::new()
        .route("/", get(web::index)) // Home page
        .route("/admin/login", get(web::admin_login_page)); // Admin login page

    // Combine all routes
    let app = Router::new()
        // Public Web UI (root path)
        .merge(public_web_routes)
        // Public API (prefix /api)
        .nest("/api", public_api_routes)
        // Admin Web UI (prefix /admin, protected by middleware)
        .nest("/admin", admin_web_routes)
        // Admin API (prefix /api/admin, protected by middleware)
        .nest("/api/admin", admin_api_routes)
        // Static file serving (must come after specific routes)
        .nest_service("/static", ServeDir::new("static"))
        // Apply global middleware (Tracing, CORS, State)
        // State needs to be last in the ServiceBuilder or applied directly with .with_state()
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http()) // Log requests/responses
                .layer(cors) // Apply CORS
        )
        .with_state(app_state); // Add AppState to all routes

    // Run the server
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!("Server listening on {}", addr);

    // Get the server future
    let server = axum::Server::bind(&addr)
        .serve(app.into_make_service());

    // Run server and handle potential errors
    server.await.context("Server execution failed")?;

    Ok(())
}

// Helper function to create directories
fn create_dir_if_not_exists(dir_path: &str) -> anyhow::Result<()> {
    let path = PathBuf::from(dir_path);
    if !path.exists() {
        std::fs::create_dir_all(&path)
            .with_context(|| format!("Failed to create directory: {}", dir_path))?;
        tracing::info!("Created directory: {}", dir_path);
    }
    Ok(())
}