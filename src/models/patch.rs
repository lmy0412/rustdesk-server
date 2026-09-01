use serde::{
    de::{Deserialize, Deserializer},
    Deserialize as SerdeDeserialize,
};
use std::fmt;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PatchField<T> {
    #[default]
    Unset,
    Null,
    Value(T),
}

impl<T> PatchField<T> {
    pub fn is_set(&self) -> bool {
        !matches!(self, Self::Unset)
    }

    pub fn into_option(self) -> Option<Option<T>> {
        match self {
            Self::Unset => None,
            Self::Null => Some(None),
            Self::Value(value) => Some(Some(value)),
        }
    }
}

impl<'de, T> Deserialize<'de> for PatchField<T>
where
    T: SerdeDeserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(|value| match value {
            Some(value) => Self::Value(value),
            None => Self::Null,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationStatus {
    BadRequest,
    PayloadTooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub status: ValidationStatus,
    pub message: String,
}

impl ValidationError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: ValidationStatus::BadRequest,
            message: message.into(),
        }
    }

    pub fn payload_too_large(message: impl Into<String>) -> Self {
        Self {
            status: ValidationStatus::PayloadTooLarge,
            message: message.into(),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ValidationError {}

pub fn normalized_identifier(
    value: String,
    field: &str,
    max_chars: usize,
) -> Result<String, ValidationError> {
    let value = value.trim().to_string();
    let length = value.chars().count();
    if length == 0 || length > max_chars {
        return Err(ValidationError::bad_request(format!(
            "{field} must contain between 1 and {max_chars} characters"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(ValidationError::bad_request(format!(
            "{field} must not contain control characters"
        )));
    }
    Ok(value)
}

pub fn normalized_optional_identifier(
    value: String,
    field: &str,
    max_chars: usize,
) -> Result<String, ValidationError> {
    normalized_identifier(value, field, max_chars)
}

pub fn normalized_note(value: String) -> Result<String, ValidationError> {
    if value.chars().count() > 300 {
        return Err(ValidationError::bad_request(
            "note must not exceed 300 characters",
        ));
    }
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\r' | '\n' | '\t'))
    {
        return Err(ValidationError::bad_request(
            "note contains an unsupported control character",
        ));
    }
    Ok(value)
}

pub fn validate_positive_id(value: i64, field: &str) -> Result<i64, ValidationError> {
    if value <= 0 {
        return Err(ValidationError::bad_request(format!(
            "{field} must be greater than zero"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_derive::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PatchRequest {
        #[serde(default)]
        value: PatchField<String>,
    }

    #[test]
    fn patch_field_distinguishes_missing_null_and_value() {
        let missing: PatchRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(missing.value, PatchField::Unset);

        let null: PatchRequest = serde_json::from_str(r#"{"value":null}"#).unwrap();
        assert_eq!(null.value, PatchField::Null);

        let value: PatchRequest = serde_json::from_str(r#"{"value":"x"}"#).unwrap();
        assert_eq!(value.value, PatchField::Value("x".to_string()));
    }

    #[test]
    fn note_allows_layout_whitespace_but_rejects_other_controls() {
        assert!(normalized_note("一行\n二行\t缩进\r\n".to_string()).is_ok());
        assert!(normalized_note("bad\u{0000}".to_string()).is_err());
        assert!(normalized_note("bad\u{0008}".to_string()).is_err());
    }
}
