use crate::models::{
    group::{normalize_device_ids, MAX_DEVICE_ID_CHARS},
    patch::{
        normalized_identifier, normalized_note, validate_positive_id, PatchField, ValidationError,
    },
};
use chrono::NaiveDateTime;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashSet;

pub const DEFAULT_PAGE_SIZE: i64 = 50;
pub const MAX_PAGE_SIZE: i64 = 200;
pub const MAX_QUERY_CHARS: usize = 100;
pub const MAX_ALIAS_CHARS: usize = 200;
pub const MAX_TAG_CHARS: usize = 64;
pub const MAX_BATCH_TAGS: usize = 50;
pub const MAX_TAGS_PER_DEVICE: usize = 100;
pub const MAX_BATCH_WORK: usize = 10_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceListQuery {
    pub group_id: Option<i64>,
    pub tag: Option<String>,
    pub status: Option<String>,
    pub q: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedDeviceListQuery {
    pub group_id: Option<i64>,
    pub tag: Option<String>,
    pub status: Option<String>,
    pub q: Option<String>,
    pub page: i64,
    pub page_size: i64,
    pub offset: i64,
}

impl DeviceListQuery {
    pub fn validate(self) -> Result<ValidatedDeviceListQuery, ValidationError> {
        let group_id = self
            .group_id
            .map(|id| validate_positive_id(id, "group_id"))
            .transpose()?;
        let tag = self
            .tag
            .map(|tag| normalized_identifier(tag, "tag", MAX_TAG_CHARS))
            .transpose()?;
        let status = match self.status {
            Some(status) => {
                let status = status.trim().to_ascii_lowercase();
                if !matches!(status.as_str(), "online" | "offline" | "inactive") {
                    return Err(ValidationError::bad_request(
                        "status must be online, offline, or inactive",
                    ));
                }
                Some(status)
            }
            None => None,
        };
        let q = match self.q {
            Some(q) => {
                if q.chars().count() > MAX_QUERY_CHARS {
                    return Err(ValidationError::bad_request(format!(
                        "q must not exceed {MAX_QUERY_CHARS} characters"
                    )));
                }
                if q.chars().any(char::is_control) {
                    return Err(ValidationError::bad_request(
                        "q must not contain control characters",
                    ));
                }
                Some(q)
            }
            None => None,
        };
        let page = self.page.unwrap_or(1);
        if page < 1 {
            return Err(ValidationError::bad_request(
                "page must be greater than or equal to one",
            ));
        }
        let requested_page_size = self.page_size.unwrap_or(DEFAULT_PAGE_SIZE);
        if requested_page_size < 1 {
            return Err(ValidationError::bad_request(
                "page_size must be greater than or equal to one",
            ));
        }
        let page_size = requested_page_size.min(MAX_PAGE_SIZE);
        let offset = page
            .checked_sub(1)
            .and_then(|value| value.checked_mul(page_size))
            .ok_or_else(|| ValidationError::bad_request("page offset is too large"))?;

        Ok(ValidatedDeviceListQuery {
            group_id,
            tag,
            status,
            q,
            page,
            page_size,
            offset,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateDeviceRequest {
    #[serde(default)]
    pub alias: PatchField<String>,
    #[serde(default)]
    pub note: PatchField<String>,
    #[serde(default)]
    pub group_id: PatchField<i64>,
    #[serde(default)]
    pub owner_user_id: PatchField<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedUpdateDevice {
    pub alias: Option<Option<String>>,
    pub note: Option<Option<String>>,
    pub group_id: Option<Option<i64>>,
    pub owner_user_id: Option<Option<i64>>,
    pub owner_field_was_set: bool,
}

impl UpdateDeviceRequest {
    pub fn validate(self) -> Result<ValidatedUpdateDevice, ValidationError> {
        if !self.alias.is_set()
            && !self.note.is_set()
            && !self.group_id.is_set()
            && !self.owner_user_id.is_set()
        {
            return Err(ValidationError::bad_request(
                "at least one device field must be provided",
            ));
        }

        let alias = match self.alias {
            PatchField::Unset => None,
            PatchField::Null => Some(None),
            PatchField::Value(alias) => Some(Some(normalized_identifier(
                alias,
                "alias",
                MAX_ALIAS_CHARS,
            )?)),
        };
        let note = match self.note {
            PatchField::Unset => None,
            PatchField::Null => Some(None),
            PatchField::Value(note) => Some(Some(normalized_note(note)?)),
        };
        let group_id = match self.group_id {
            PatchField::Unset => None,
            PatchField::Null => Some(None),
            PatchField::Value(id) => Some(Some(validate_positive_id(id, "group_id")?)),
        };
        let owner_field_was_set = self.owner_user_id.is_set();
        let owner_user_id = match self.owner_user_id {
            PatchField::Unset => None,
            PatchField::Null => Some(None),
            PatchField::Value(id) => Some(Some(validate_positive_id(id, "owner_user_id")?)),
        };

        Ok(ValidatedUpdateDevice {
            alias,
            note,
            group_id,
            owner_user_id,
            owner_field_was_set,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchTagRequest {
    pub device_ids: Vec<String>,
    #[serde(default)]
    pub add_tags: Vec<String>,
    #[serde(default)]
    pub remove_tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedBatchTag {
    pub device_ids: Vec<String>,
    pub add_tags: Vec<String>,
    pub remove_tags: Vec<String>,
}

impl BatchTagRequest {
    pub fn validate(self) -> Result<ValidatedBatchTag, ValidationError> {
        if self.add_tags.len() > MAX_BATCH_TAGS || self.remove_tags.len() > MAX_BATCH_TAGS {
            return Err(ValidationError::payload_too_large(format!(
                "add_tags and remove_tags must not contain more than {MAX_BATCH_TAGS} items each"
            )));
        }

        let device_ids = normalize_device_ids(self.device_ids)?;
        let add_tags = normalize_tags(self.add_tags)?;
        let remove_tags = normalize_tags(self.remove_tags)?;
        if add_tags.is_empty() && remove_tags.is_empty() {
            return Err(ValidationError::bad_request(
                "at least one tag must be added or removed",
            ));
        }

        let add_keys: HashSet<String> = add_tags
            .iter()
            .map(|tag| tag.to_ascii_lowercase())
            .collect();
        if remove_tags
            .iter()
            .map(|tag| tag.to_ascii_lowercase())
            .any(|tag| add_keys.contains(&tag))
        {
            return Err(ValidationError::bad_request(
                "the same tag cannot be added and removed",
            ));
        }

        let operations = add_tags
            .len()
            .checked_add(remove_tags.len())
            .ok_or_else(|| ValidationError::payload_too_large("tag work budget is too large"))?;
        let work = device_ids
            .len()
            .checked_mul(operations)
            .ok_or_else(|| ValidationError::payload_too_large("tag work budget is too large"))?;
        if work > MAX_BATCH_WORK {
            return Err(ValidationError::payload_too_large(format!(
                "tag work budget must not exceed {MAX_BATCH_WORK}"
            )));
        }

        Ok(ValidatedBatchTag {
            device_ids,
            add_tags,
            remove_tags,
        })
    }
}

fn normalize_tags(tags: Vec<String>) -> Result<Vec<String>, ValidationError> {
    if tags.len() > MAX_BATCH_TAGS {
        return Err(ValidationError::payload_too_large(format!(
            "tag arrays must not contain more than {MAX_BATCH_TAGS} items"
        )));
    }

    let mut seen = HashSet::with_capacity(tags.len());
    let mut normalized = Vec::with_capacity(tags.len());
    for tag in tags {
        let tag = normalized_identifier(tag, "tag", MAX_TAG_CHARS)?;
        if seen.insert(tag.to_ascii_lowercase()) {
            normalized.push(tag);
        }
    }
    if normalized.len() > MAX_BATCH_TAGS {
        return Err(ValidationError::payload_too_large(format!(
            "tag arrays must not contain more than {MAX_BATCH_TAGS} unique items"
        )));
    }
    Ok(normalized)
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DeviceResponse {
    pub device_id: String,
    pub owner_user_id: Option<i64>,
    pub group_id: Option<i64>,
    pub alias: Option<String>,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub note: Option<String>,
    pub status: String,
    pub generation: String,
    pub tags: Vec<String>,
    pub last_seen: NaiveDateTime,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DeviceListResponse {
    pub items: Vec<DeviceResponse>,
    pub page: i64,
    pub page_size: i64,
    pub total: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BatchTagResponse {
    pub matched_devices: u64,
    pub added_relations: u64,
    pub removed_relations: u64,
}

pub fn validate_device_id(value: String) -> Result<String, ValidationError> {
    normalized_identifier(value, "device_id", MAX_DEVICE_ID_CHARS)
}

pub fn validate_generation(value: &str) -> Result<String, ValidationError> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ValidationError::bad_request(
            "X-Device-Generation must be 32 lowercase hexadecimal characters",
        ));
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::patch::ValidationStatus;

    #[test]
    fn pagination_defaults_caps_and_checks_overflow() {
        let defaults = DeviceListQuery {
            group_id: None,
            tag: None,
            status: None,
            q: None,
            page: None,
            page_size: None,
        }
        .validate()
        .unwrap();
        assert_eq!(defaults.page, 1);
        assert_eq!(defaults.page_size, 50);
        assert_eq!(defaults.offset, 0);

        let capped = DeviceListQuery {
            page_size: Some(201),
            ..empty_query()
        }
        .validate()
        .unwrap();
        assert_eq!(capped.page_size, 200);

        assert!(DeviceListQuery {
            page: Some(i64::MAX),
            page_size: Some(200),
            ..empty_query()
        }
        .validate()
        .is_err());
    }

    #[test]
    fn update_device_preserves_three_state_fields() {
        let request: UpdateDeviceRequest =
            serde_json::from_str(r#"{"alias":null,"note":"","group_id":3}"#).unwrap();
        let validated = request.validate().unwrap();
        assert_eq!(validated.alias, Some(None));
        assert_eq!(validated.note, Some(Some(String::new())));
        assert_eq!(validated.group_id, Some(Some(3)));
        assert_eq!(validated.owner_user_id, None);

        let empty: UpdateDeviceRequest = serde_json::from_str("{}").unwrap();
        assert!(empty.validate().is_err());
    }

    #[test]
    fn batch_tags_use_ascii_nocase_and_work_budget() {
        let validated = BatchTagRequest {
            device_ids: vec!["1".to_string(), "2".to_string()],
            add_tags: vec![" Linux ".to_string(), "linux".to_string(), "Ä".to_string()],
            remove_tags: vec!["ä".to_string()],
        }
        .validate()
        .unwrap();
        assert_eq!(validated.add_tags, vec!["Linux", "Ä"]);
        assert_eq!(validated.remove_tags, vec!["ä"]);

        let overlap = BatchTagRequest {
            device_ids: vec!["1".to_string()],
            add_tags: vec!["A".to_string()],
            remove_tags: vec!["a".to_string()],
        };
        assert!(overlap.validate().is_err());

        let too_much_work = BatchTagRequest {
            device_ids: (0..500).map(|id| id.to_string()).collect(),
            add_tags: (0..21).map(|id| format!("tag-{id}")).collect(),
            remove_tags: Vec::new(),
        };
        assert_eq!(
            too_much_work.validate().unwrap_err().status,
            ValidationStatus::PayloadTooLarge
        );
    }

    #[test]
    fn generation_is_strict_lowercase_hex() {
        assert!(validate_generation("6f3bcaf8304f4ab39545b59614a4ac80").is_ok());
        assert!(validate_generation("6F3BCAF8304F4AB39545B59614A4AC80").is_err());
        assert!(validate_generation("not-a-generation").is_err());
    }

    #[test]
    fn request_dto_rejects_unknown_or_read_only_fields() {
        assert!(serde_json::from_str::<UpdateDeviceRequest>(r#"{"hostname":"DESKTOP"}"#).is_err());
        assert!(serde_json::from_str::<BatchTagRequest>(
            r#"{"device_ids":["1"],"add_tags":["x"],"unexpected":1}"#
        )
        .is_err());
    }

    fn empty_query() -> DeviceListQuery {
        DeviceListQuery {
            group_id: None,
            tag: None,
            status: None,
            q: None,
            page: None,
            page_size: None,
        }
    }
}
