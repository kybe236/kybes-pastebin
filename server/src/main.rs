use std::collections::HashMap;

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

// ------------------------------
// Database setup and utilities
// ------------------------------

/// Ensure tables exist and create a default admin token if none found.
async fn setup_database(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // Create tables
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            is_admin INTEGER
        );
        CREATE TABLE IF NOT EXISTS pastes (
            id TEXT PRIMARY KEY,
            owner_token TEXT,
            content BLOB,
            headers TEXT
        );
        CREATE TABLE IF NOT EXISTS aliases (
            alias TEXT PRIMARY KEY,
            paste_id TEXT
        );
        "#,
    )
    .execute(pool)
    .await?;

    // Insert default admin token if necessary
    let admin_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tokens WHERE is_admin = 1")
        .fetch_one(pool)
        .await?;

    if admin_count == 0 {
        let token = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO tokens (token, is_admin) VALUES (?, 1)")
            .bind(&token)
            .execute(pool)
            .await?;
        println!("Admin token: {}", token);
    }

    Ok(())
}

/// Check if a token has admin privileges.
async fn is_admin(pool: &SqlitePool, token: &str) -> bool {
    sqlx::query_scalar::<_, i32>("SELECT is_admin FROM tokens WHERE token = ?")
        .bind(token)
        .fetch_optional(pool)
        .await
        .unwrap_or(None)
        .map_or(false, |flag| flag == 1)
}

/// Extract Bearer token from Authorization header.
fn get_auth(headers: &HeaderMap) -> Result<String, Json<&'static str>> {
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(String::from)
        .ok_or(Json("Missing or invalid Authorization header"))
}

// ------------------------------
// Request handlers
// ------------------------------

#[derive(Deserialize)]
struct SetAdminInput {
    admin_token: String,
    target_token: String,
    is_admin: bool,
}

async fn set_admin(
    State(pool): State<SqlitePool>,
    Json(body): Json<SetAdminInput>,
) -> Json<&'static str> {
    if !is_admin(&pool, &body.admin_token).await {
        return Json("Unauthorized");
    }

    let updated = sqlx::query("UPDATE tokens SET is_admin = ? WHERE token = ?")
        .bind(if body.is_admin { 1 } else { 0 })
        .bind(&body.target_token)
        .execute(&pool)
        .await;

    match updated {
        Ok(result) if result.rows_affected() > 0 => Json("Updated"),
        Ok(_) => Json("Token not found"),
        Err(_) => Json("Database error"),
    }
}

async fn create_paste(
    State(pool): State<SqlitePool>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<String>, Json<&'static str>> {
    let token = get_auth(&headers)?;

    let bytes = to_bytes(body, usize::MAX)
        .await
        .map_err(|_| Json("Failed to read body"))?;
    let content = bytes.to_vec();

    let valid: Option<i64> = sqlx::query_scalar("SELECT 1 FROM tokens WHERE token = ?")
        .bind(&token)
        .fetch_optional(&pool)
        .await
        .map_err(|_| Json("Database error"))?;

    if valid.is_none() {
        return Err(Json("Unauthorized"));
    }

    // X-Aliases headers are getting added to the paste
    let aliases_header = headers
        .iter()
        .find(|(k, _)| k.as_str().eq_ignore_ascii_case("X-Aliases"))
        .and_then(|(_, v)| v.to_str().ok());
    let aliases = aliases_header
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty());

    // X-Paste-* headers are getting added to the paste
    let mut paste_headers = HashMap::new();
    for (key, value) in headers.iter() {
        if let Some(name) = key.as_str().strip_prefix("X-Paste-") {
            if let Ok(val_str) = value.to_str() {
                paste_headers.insert(name.to_string(), val_str.to_string());
            }
        }
    }

    let paste_id = Uuid::new_v4().to_string();

    let header_json = serde_json::to_string(&paste_headers).unwrap_or("{}".to_string());

    sqlx::query("INSERT INTO pastes (id, owner_token, content, headers) VALUES (?, ?, ?, ?)")
        .bind(&paste_id)
        .bind(&token)
        .bind(&content)
        .bind(&header_json)
        .execute(&pool)
        .await
        .map_err(|_| Json("Database error"))?;

    for alias in aliases {
        if alias.is_empty() {
            continue;
        }
        let exists: Option<i64> = sqlx::query_scalar("SELECT 1 FROM aliases WHERE alias = ?")
            .bind(alias)
            .fetch_optional(&pool)
            .await
            .map_err(|_| Json("Database error"))?;

        if exists.is_some() {
            return Err(Json("Alias already exists"));
        }

        sqlx::query("INSERT INTO aliases (alias, paste_id) VALUES (?, ?)")
            .bind(alias)
            .bind(&paste_id)
            .execute(&pool)
            .await
            .map_err(|_| Json("Database error"))?;
    }

    Ok(Json(paste_id))
}

#[derive(Deserialize)]
struct CreateTokenInput {
    admin_token: String,
    is_admin: Option<bool>,
}

async fn create_token(
    State(pool): State<SqlitePool>,
    Json(body): Json<CreateTokenInput>,
) -> Json<serde_json::Value> {
    if !is_admin(&pool, &body.admin_token).await {
        return Json(json!({"error": "Unauthorized"}));
    }

    let new_token = Uuid::new_v4().to_string();
    let is_admin_flag = body.is_admin.unwrap_or(false);

    let result = sqlx::query("INSERT INTO tokens (token, is_admin) VALUES (?, ?)")
        .bind(&new_token)
        .bind(if is_admin_flag { 1 } else { 0 })
        .execute(&pool)
        .await;

    match result {
        Ok(_) => Json(json!({
            "token": new_token,
            "is_admin": is_admin_flag
        })),
        Err(e) => Json(json!({"error": "Database error", "details": e.to_string()})),
    }
}

async fn get_tokens(
    State(pool): State<SqlitePool>,
    Json(body): Json<TokenInput>,
) -> Json<serde_json::Value> {
    let admin = is_admin(&pool, &body.token).await;
    if !admin {
        return Json(json!({"error": "Unauthorized"}));
    }

    let rows = sqlx::query("SELECT token, is_admin FROM tokens")
        .fetch_all(&pool)
        .await
        .unwrap_or_default();

    let tokens: Vec<_> = rows
        .iter()
        .map(|row| {
            json!({
                "token": row.get::<String, _>("token"),
                "is_admin": row.get::<i32, _>("is_admin") == 1
            })
        })
        .collect();

    Json(json!(tokens))
}

#[derive(Deserialize)]
struct DeleteTokenInput {
    admin_token: String,
    token_to_delete: String,
}

async fn delete_token(
    State(pool): State<SqlitePool>,
    Json(body): Json<DeleteTokenInput>,
) -> Json<&'static str> {
    if is_admin(&pool, &body.admin_token).await {
        let result = sqlx::query("DELETE FROM tokens WHERE token = ?")
            .bind(&body.token_to_delete)
            .execute(&pool)
            .await;

        match result {
            Ok(result) if result.rows_affected() > 0 => Json("Deleted"),
            Ok(_) => Json("Token not found"),
            Err(_) => Json("Database error"),
        }
    } else {
        Json("Unauthorized")
    }
}

async fn get_pastes(
    State(pool): State<SqlitePool>,
    Json(body): Json<TokenInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let admin = is_admin(&pool, &body.token).await;

    let rows = if admin {
        sqlx::query("SELECT id, headers FROM pastes")
            .fetch_all(&pool)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    } else {
        sqlx::query("SELECT id, headers FROM pastes WHERE owner_token = ?")
            .bind(&body.token)
            .fetch_all(&pool)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };

    let mut result = Vec::new();
    for row in rows {
        let id: String = row.get("id");
        let headers_str: String = row.get("headers");
        let headers =
            serde_json::from_str::<HashMap<String, String>>(&headers_str).unwrap_or_default();

        let alias_rows = sqlx::query("SELECT alias FROM aliases WHERE paste_id = ?")
            .bind(&id)
            .fetch_all(&pool)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let aliases: Vec<String> = alias_rows.iter().map(|r| r.get("alias")).collect();

        result.push(json!({
            "id": id,
            "headers": headers,
            "aliases": aliases,
        }));
    }

    Ok(Json(json!(result)))
}

async fn get_paste(
    State(pool): State<SqlitePool>,
    Path(paste_id): Path<String>,
    Json(body): Json<TokenInput>,
) -> Json<serde_json::Value> {
    // Check authorization
    let is_owner_or_admin = is_admin(&pool, &body.token).await
        || sqlx::query_scalar::<_, i64>("SELECT 1 FROM pastes WHERE id = ? AND owner_token = ?")
            .bind(&paste_id)
            .bind(&body.token)
            .fetch_optional(&pool)
            .await
            .unwrap_or(None)
            .is_some();

    if !is_owner_or_admin {
        return Json(json!({"error": "Unauthorized"}));
    }

    let row = sqlx::query("SELECT content, headers FROM pastes WHERE id = ?")
        .bind(&paste_id)
        .fetch_optional(&pool)
        .await;

    match row {
        Ok(Some(row)) => {
            let content: Vec<u8> = row.get("content");
            let headers_str: String = row.get("headers");
            let headers_map: HashMap<String, String> =
                serde_json::from_str(&headers_str).unwrap_or_default();

            // Get aliases
            let alias_rows = sqlx::query("SELECT alias FROM aliases WHERE paste_id = ?")
                .bind(&paste_id)
                .fetch_all(&pool)
                .await
                .unwrap_or_default();

            let aliases: Vec<String> = alias_rows.iter().map(|r| r.get("alias")).collect();

            Json(json!({
                "id": paste_id,
                "content": content,
                "headers": headers_map,
                "aliases": aliases,
            }))
        }
        Ok(None) => Json(json!({"error": "Paste not found"})),
        Err(e) => Json(json!({"error": "Database error", "details": e.to_string()})),
    }
}

#[derive(Deserialize)]
struct DeletePasteInput {
    token: String,
    paste_id: String,
}

async fn delete_paste(
    State(pool): State<SqlitePool>,
    Json(body): Json<DeletePasteInput>,
) -> Json<&'static str> {
    let is_owner =
        sqlx::query_scalar::<_, i64>("SELECT 1 FROM pastes WHERE id = ? AND owner_token = ?")
            .bind(&body.paste_id)
            .bind(&body.token)
            .fetch_optional(&pool)
            .await
            .unwrap_or(None)
            .is_some();

    if is_owner || is_admin(&pool, &body.token).await {
        let _ = sqlx::query("DELETE FROM pastes WHERE id = ?")
            .bind(&body.paste_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM aliases WHERE paste_id = ?")
            .bind(&body.paste_id)
            .execute(&pool)
            .await;
        Json("Deleted")
    } else {
        Json("Unauthorized")
    }
}

async fn get_paste_by_id_or_alias(
    State(pool): State<SqlitePool>,
    Path(id_or_alias): Path<String>,
) -> Response {
    let paste_id = sqlx::query_scalar::<_, String>("SELECT paste_id FROM aliases WHERE alias = ?")
        .bind(&id_or_alias)
        .fetch_optional(&pool)
        .await
        .unwrap_or(None)
        .unwrap_or(id_or_alias);

    let row = sqlx::query("SELECT content, headers FROM pastes WHERE id = ?")
        .bind(&paste_id)
        .fetch_optional(&pool)
        .await;

    match row {
        Ok(Some(row)) => {
            let content: Vec<u8> = row.get("content");
            let headers_str: String = row.get("headers");
            let headers_map: HashMap<String, String> =
                serde_json::from_str(&headers_str).unwrap_or_default();
            let mut resp = Response::builder().status(StatusCode::OK);
            for (k, v) in headers_map {
                if let (Ok(name), Ok(value)) = (
                    HeaderName::from_bytes(k.as_bytes()),
                    HeaderValue::from_str(&v),
                ) {
                    resp = resp.header(name, value);
                }
            }
            resp.body(Body::from(content)).unwrap()
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

// ------------------------------
// Application entry point
// ------------------------------

#[derive(Deserialize)]
struct TokenInput {
    token: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = SqlitePool::connect("sqlite:db.db?mode=rwc").await?;

    setup_database(&pool).await?;

    let app = Router::new()
        .route("/api/create_paste", post(create_paste))
        .route("/api/create_token", post(create_token))
        .route("/api/get_tokens", post(get_tokens))
        .route("/api/delete_token", post(delete_token))
        .route("/api/get_pastes", post(get_pastes))
        .route("/api/get_paste/{paste_id}", post(get_paste))
        .route("/api/delete_paste", post(delete_paste))
        .route("/api/set_admin", post(set_admin))
        .route("/{id_or_alias}", get(get_paste_by_id_or_alias))
        .with_state(pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:6960").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
