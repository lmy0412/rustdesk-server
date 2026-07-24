use crate::models::patch::{
    normalized_identifier, validate_positive_id, PatchField, ValidationError,
};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashSet;

pub const MAX_GROUP_NAME_CHARS: usize = 200;
pub const MAX_DEVICE_ID_CHARS: usize = 100;
pub const MAX_BATCH_DEVICES: usize = 500;
pub const MAX_GROUP_TREE_DEPTH: usize = 256;
pub const MAX_GROUP_TREE_NODES: usize = 10_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateGroupRequest {
    pub name: String,
    pub parent_group_id: Option<i64>,
    pub owner_user_id: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCreateGroup {
    pub name: String,
    pub parent_group_id: Option<i64>,
    pub owner_user_id: Option<i64>,
}

impl CreateGroupRequest {
    pub fn validate(self) -> Result<ValidatedCreateGroup, ValidationError> {
        Ok(ValidatedCreateGroup {
            name: normalized_identifier(self.name, "name", MAX_GROUP_NAME_CHARS)?,
            parent_group_id: self
                .parent_group_id
                .map(|id| validate_positive_id(id, "parent_group_id"))
                .transpose()?,
            owner_user_id: self
                .owner_user_id
                .map(|id| validate_positive_id(id, "owner_user_id"))
                .transpose()?,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateGroupRequest {
    #[serde(default)]
    pub name: PatchField<String>,
    #[serde(default)]
    pub parent_group_id: PatchField<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedUpdateGroup {
    pub name: Option<String>,
    pub parent_group_id: Option<Option<i64>>,
}

impl UpdateGroupRequest {
    pub fn validate(self) -> Result<ValidatedUpdateGroup, ValidationError> {
        if !self.name.is_set() && !self.parent_group_id.is_set() {
            return Err(ValidationError::bad_request(
                "at least one group field must be provided",
            ));
        }

        let name = match self.name {
            PatchField::Unset => None,
            PatchField::Null => {
                return Err(ValidationError::bad_request("name must not be null"));
            }
            PatchField::Value(name) => {
                Some(normalized_identifier(name, "name", MAX_GROUP_NAME_CHARS)?)
            }
        };
        let parent_group_id = match self.parent_group_id {
            PatchField::Unset => None,
            PatchField::Null => Some(None),
            PatchField::Value(id) => Some(Some(validate_positive_id(id, "parent_group_id")?)),
        };

        Ok(ValidatedUpdateGroup {
            name,
            parent_group_id,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceBatchRequest {
    pub device_ids: Vec<String>,
}

impl DeviceBatchRequest {
    pub fn validate(self) -> Result<Vec<String>, ValidationError> {
        normalize_device_ids(self.device_ids)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GroupTreeNode {
    pub id: i64,
    pub name: String,
    pub owner_user_id: i64,
    pub parent_group_id: Option<i64>,
    pub children: Vec<GroupTreeNode>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GroupListResponse {
    pub items: Vec<GroupTreeNode>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GroupBatchResponse {
    pub matched_devices: u64,
    pub changed_devices: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ForceDeleteGroupResponse {
    pub deleted_groups: u64,
    pub ungrouped_devices: u64,
}

pub fn normalize_device_ids(device_ids: Vec<String>) -> Result<Vec<String>, ValidationError> {
    if device_ids.is_empty() {
        return Err(ValidationError::bad_request(
            "device_ids must contain at least one item",
        ));
    }
    if device_ids.len() > MAX_BATCH_DEVICES {
        return Err(ValidationError::payload_too_large(format!(
            "device_ids must not contain more than {MAX_BATCH_DEVICES} items"
        )));
    }

    let mut seen = HashSet::with_capacity(device_ids.len());
    let mut normalized = Vec::with_capacity(device_ids.len());
    for device_id in device_ids {
        let device_id = normalized_identifier(device_id, "device_id", MAX_DEVICE_ID_CHARS)?;
        if seen.insert(device_id.clone()) {
            normalized.push(device_id);
        }
    }
    if normalized.len() > MAX_BATCH_DEVICES {
        return Err(ValidationError::payload_too_large(format!(
            "device_ids must not contain more than {MAX_BATCH_DEVICES} unique items"
        )));
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_group_trims_and_validates_ids() {
        let validated = CreateGroupRequest {
            name: " 技术部 ".to_string(),
            parent_group_id: Some(1),
            owner_user_id: Some(2),
        }
        .validate()
        .unwrap();
        assert_eq!(validated.name, "技术部");
        assert_eq!(validated.parent_group_id, Some(1));
        assert_eq!(validated.owner_user_id, Some(2));

        assert!(CreateGroupRequest {
            name: "ok".to_string(),
            parent_group_id: Some(0),
            owner_user_id: None,
        }
        .validate()
        .is_err());
    }

    #[test]
    fn update_group_keeps_three_state_parent() {
        let missing: UpdateGroupRequest = serde_json::from_str(r#"{"name":" 后端组 "}"#).unwrap();
        let missing = missing.validate().unwrap();
        assert_eq!(missing.name.as_deref(), Some("后端组"));
        assert_eq!(missing.parent_group_id, None);

        let null: UpdateGroupRequest = serde_json::from_str(r#"{"parent_group_id":null}"#).unwrap();
        assert_eq!(null.validate().unwrap().parent_group_id, Some(None));

        let empty: UpdateGroupRequest = serde_json::from_str("{}").unwrap();
        assert!(empty.validate().is_err());
        let null_name: UpdateGroupRequest = serde_json::from_str(r#"{"name":null}"#).unwrap();
        assert!(null_name.validate().is_err());
    }

    #[test]
    fn device_batch_checks_raw_count_before_deduplication() {
        let oversized = vec!["same".to_string(); MAX_BATCH_DEVICES + 1];
        assert_eq!(
            normalize_device_ids(oversized).unwrap_err().status,
            crate::models::patch::ValidationStatus::PayloadTooLarge
        );

        let normalized =
            normalize_device_ids(vec![" 100 ".to_string(), "100".to_string()]).unwrap();
        assert_eq!(normalized, vec!["100"]);
    }

    #[test]
    fn request_dto_rejects_unknown_fields() {
        assert!(
            serde_json::from_str::<CreateGroupRequest>(r#"{"name":"x","unknown":true}"#).is_err()
        );
        assert!(serde_json::from_str::<DeviceBatchRequest>(
            r#"{"device_ids":["1"],"unknown":true}"#
        )
        .is_err());
    }
}
