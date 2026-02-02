//! Validated JSON Extractor for Axum
//!
//! Provides automatic request validation using the validator crate.

use axum::{
    async_trait,
    extract::{FromRequest, Request},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::de::DeserializeOwned;
use validator::Validate;

/// Validated JSON extractor
///
/// Automatically validates request bodies using the `validator` crate.
/// Returns 400 Bad Request with validation errors if validation fails.
pub struct ValidatedJson<T>(pub T);

#[async_trait]
impl<T, S> FromRequest<S> for ValidatedJson<T>
where
    T: DeserializeOwned + Validate,
    S: Send + Sync,
{
    type Rejection = ValidationRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        // First, extract JSON
        let Json(data) = Json::<T>::from_request(req, state)
            .await
            .map_err(|err| ValidationRejection::JsonError(err.to_string()))?;

        // Then validate
        data.validate()
            .map_err(|err| ValidationRejection::ValidationError(err.to_string()))?;

        Ok(ValidatedJson(data))
    }
}

/// Validation rejection response
#[derive(Debug)]
pub enum ValidationRejection {
    JsonError(String),
    ValidationError(String),
}

impl IntoResponse for ValidationRejection {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ValidationRejection::JsonError(msg) => {
                (StatusCode::BAD_REQUEST, format!("Invalid JSON: {}", msg))
            }
            ValidationRejection::ValidationError(msg) => (
                StatusCode::BAD_REQUEST,
                format!("Validation failed: {}", msg),
            ),
        };

        tracing::warn!("Validation rejection: {}", message);

        (
            status,
            Json(serde_json::json!({
                "error": message,
                "status": status.as_u16()
            })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, Validate)]
    struct TestRequest {
        #[validate(length(min = 1, max = 10))]
        name: String,
    }

    #[test]
    fn test_validation_rejection_display() {
        let rejection = ValidationRejection::ValidationError("test error".to_string());
        let response = rejection.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
