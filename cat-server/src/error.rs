//! Typed server errors with automatic HTTP status mapping.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

#[derive(Debug)]
pub enum ServerError {
    NotFound,
    Unauthorized,
    BadRequest(String),
    Forbidden(String),
    Conflict(String),
    Db(sqlx::Error),
    Internal(anyhow::Error),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "not found"),
            Self::Unauthorized => write!(f, "unauthorized"),
            Self::BadRequest(msg) => write!(f, "bad request: {msg}"),
            Self::Forbidden(msg) => write!(f, "forbidden: {msg}"),
            Self::Conflict(msg) => write!(f, "conflict: {msg}"),
            Self::Db(e) => write!(f, "database error: {e}"),
            Self::Internal(e) => write!(f, "internal error: {e}"),
        }
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let (status, key) = match &self {
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            Self::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            Self::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            Self::Db(_) => (StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };

        tracing::error!("{self}");

        (status, Json(serde_json::json!({ "status": key }))).into_response()
    }
}

impl From<sqlx::Error> for ServerError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::RowNotFound => Self::NotFound,
            other => Self::Db(other),
        }
    }
}

impl From<anyhow::Error> for ServerError {
    fn from(e: anyhow::Error) -> Self {
        match e.downcast::<sqlx::Error>() {
            Ok(sqlx_err) => Self::from(sqlx_err),
            Err(other) => Self::Internal(other),
        }
    }
}
