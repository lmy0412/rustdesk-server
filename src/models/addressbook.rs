use serde_derive::{Deserialize, Serialize};

use super::user::MAX_SAFE_INTEGER;

pub fn validate_safe_device_text_fields(
    alias: &str,
    hostname: &str,
    os: &str,
) -> Result<(), String> {
    if alias.chars().count() > 200 || alias.chars().any(char::is_control) {
        return Err("地址簿设备别名超长或包含控制字符".to_owned());
    }
    if hostname.len() > 200 || hostname.chars().any(char::is_control) {
        return Err("地址簿设备主机名超长或包含控制字符".to_owned());
    }
    if os.len() > 100 || os.chars().any(char::is_control) {
        return Err("地址簿设备系统名称超长或包含控制字符".to_owned());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressBookSource {
    Owned,
    Shared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharePermission {
    ViewOnly,
    FullControl,
}

impl SharePermission {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewOnly => "view_only",
            Self::FullControl => "full_control",
        }
    }
}

impl TryFrom<&str> for SharePermission {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "view_only" => Ok(Self::ViewOnly),
            "full_control" => Ok(Self::FullControl),
            other => Err(format!("未知共享权限：{other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareStatus {
    Pending,
    Accepted,
    Rejected,
}

impl ShareStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

impl TryFrom<&str> for ShareStatus {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "pending" => Ok(Self::Pending),
            "accepted" => Ok(Self::Accepted),
            "rejected" => Ok(Self::Rejected),
            other => Err(format!("未知共享状态：{other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressBookOperation {
    Upsert,
    Delete,
}

impl AddressBookOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upsert => "upsert",
            Self::Delete => "delete",
        }
    }
}

impl TryFrom<&str> for AddressBookOperation {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "upsert" => Ok(Self::Upsert),
            "delete" => Ok(Self::Delete),
            other => Err(format!("未知地址簿操作：{other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeDeviceDto {
    pub device_id: String,
    pub instance_id: String,
    pub alias: String,
    pub hostname: String,
    pub os: String,
    pub source: AddressBookSource,
    pub permission: SharePermission,
    pub share_id: Option<i64>,
    pub shared_by_user_id: Option<i64>,
    pub shared_by_username: Option<String>,
}

impl SafeDeviceDto {
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.device_id.is_empty()
            || self.device_id.chars().count() > 100
            || self.device_id.chars().any(char::is_control)
        {
            return Err("地址簿设备 ID 非法".to_owned());
        }
        if self.instance_id.len() != 64
            || self
                .instance_id
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err("地址簿设备实例 ID 非法".to_owned());
        }
        validate_safe_device_text_fields(&self.alias, &self.hostname, &self.os)?;
        if self
            .share_id
            .is_some_and(|id| !(1..=MAX_SAFE_INTEGER).contains(&id))
            || self
                .shared_by_user_id
                .is_some_and(|id| !(1..=MAX_SAFE_INTEGER).contains(&id))
        {
            return Err("地址簿共享身份超出安全整数范围".to_owned());
        }
        match self.source {
            AddressBookSource::Owned => {
                if self.permission != SharePermission::FullControl
                    || self.share_id.is_some()
                    || self.shared_by_user_id.is_some()
                    || self.shared_by_username.is_some()
                {
                    return Err("owned 地址簿条目字段组合非法".to_owned());
                }
            }
            AddressBookSource::Shared => {
                if self.share_id.is_none()
                    || self.shared_by_user_id.is_none()
                    || self.shared_by_username.is_none()
                {
                    return Err("shared 地址簿条目缺少共享身份".to_owned());
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressBookChangeDto {
    pub version: i64,
    pub operation: AddressBookOperation,
    pub device_id: String,
    pub instance_id: String,
    pub share_id: Option<i64>,
    pub item: Option<SafeDeviceDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressBookSnapshot {
    pub ab_ver: i64,
    pub items: Vec<SafeDeviceDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressBookFullPage {
    pub mode: &'static str,
    pub ab_ver: i64,
    pub items: Vec<SafeDeviceDto>,
    pub page: u64,
    pub page_size: u64,
    pub total: i64,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressBookDeltaPage {
    pub mode: String,
    pub ab_ver: i64,
    pub next_ab_ver: i64,
    pub changes: Vec<AddressBookChangeDto>,
    pub page_size: i64,
    pub has_more: bool,
    pub reset_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareDeviceSummaryDto {
    pub device_id: String,
    pub instance_id: String,
    pub alias: String,
    pub hostname: String,
    pub os: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareDto {
    pub id: i64,
    pub device: ShareDeviceSummaryDto,
    pub from_user_id: i64,
    pub from_username: String,
    pub to_user_id: i64,
    pub to_username: String,
    pub permission: SharePermission,
    pub status: ShareStatus,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShareMutation {
    pub created: bool,
    pub share: ShareDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingShareDto {
    pub id: i64,
    pub device: ShareDeviceSummaryDto,
    pub from_user_id: i64,
    pub from_username: String,
    pub permission: SharePermission,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PendingSharePage {
    pub items: Vec<PendingShareDto>,
    pub next_after_id: i64,
    pub page_size: i64,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysinfoDeviceSnapshot {
    pub management_generation: String,
    pub owner_user_id: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysinfoUpdateResult {
    pub matched: bool,
    pub is_owner: bool,
    pub changed: bool,
    pub previous_address_book_version: i64,
    pub address_book_version: i64,
}

#[cfg(test)]
mod tests {
    use super::validate_safe_device_text_fields;

    #[test]
    fn safe_device_text_contract_uses_field_specific_limits() {
        assert!(validate_safe_device_text_fields(
            &"别".repeat(200),
            &"h".repeat(200),
            &"o".repeat(100),
        )
        .is_ok());
        assert!(validate_safe_device_text_fields(&"别".repeat(201), "", "").is_err());
        assert!(validate_safe_device_text_fields("", &"h".repeat(201), "").is_err());
        assert!(validate_safe_device_text_fields("", "", &"o".repeat(101)).is_err());
        assert!(validate_safe_device_text_fields("a\u{0001}", "", "").is_err());
        assert!(validate_safe_device_text_fields("", "h\n", "").is_err());
        assert!(validate_safe_device_text_fields("", "", "o\r").is_err());
    }
}
