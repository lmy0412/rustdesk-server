use crate::{
    api::access::{
        create_owner, inventory_error, read_access, validation_error, write_access, ApiError,
        LimitedJson,
    },
    auth::jwt::CurrentUser,
    database::{Database, ForceDeleteOutcome, GroupDeleteOutcome, GroupRecord, GroupUpdate},
    models::{
        group::{
            CreateGroupRequest, DeviceBatchRequest, ForceDeleteGroupResponse, GroupBatchResponse,
            GroupListResponse, GroupTreeNode, UpdateGroupRequest, MAX_GROUP_TREE_DEPTH,
            MAX_GROUP_TREE_NODES,
        },
        patch::validate_positive_id,
    },
};
use axum::{
    extract::{Extension, Path, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_derive::Deserialize;
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteGroupQuery {
    #[serde(default)]
    force: bool,
}

pub async fn handle_create_group(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    LimitedJson(payload): LimitedJson<CreateGroupRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let payload = payload.validate().map_err(validation_error)?;
    let access = write_access(&current)?;
    let owner_user_id = create_owner(&current, access, payload.owner_user_id)?;
    let group = db
        .create_group(
            access.scope,
            owner_user_id,
            &payload.name,
            payload.parent_group_id,
        )
        .await
        .map_err(|error| inventory_error(error, "create group failed"))?;
    Ok((StatusCode::CREATED, Json(group_node(group))))
}

pub async fn handle_list_groups(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
) -> Result<Json<GroupListResponse>, ApiError> {
    let scope = read_access(&current)?.scope;
    let groups = db
        .list_groups(scope)
        .await
        .map_err(|error| inventory_error(error, "list groups failed"))?;
    let items = build_group_forest(groups, None)?;
    Ok(Json(GroupListResponse { items }))
}

pub async fn handle_get_group(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Result<Json<GroupTreeNode>, ApiError> {
    let id = validate_positive_id(id, "group id").map_err(validation_error)?;
    let scope = read_access(&current)?.scope;
    let groups = db
        .get_group_subtree(scope, id)
        .await
        .map_err(|error| inventory_error(error, "get group failed"))?;
    let mut roots = build_group_forest(groups, Some(id))?;
    roots
        .pop()
        .map(Json)
        .ok_or_else(|| ApiError::not_found("group"))
}

pub async fn handle_update_group(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Path(id): Path<i64>,
    LimitedJson(payload): LimitedJson<UpdateGroupRequest>,
) -> Result<Json<GroupTreeNode>, ApiError> {
    let id = validate_positive_id(id, "group id").map_err(validation_error)?;
    let payload = payload.validate().map_err(validation_error)?;
    let scope = write_access(&current)?.scope;
    let groups = db
        .update_group(
            scope,
            id,
            &GroupUpdate {
                name: payload.name,
                parent_group_id: payload.parent_group_id,
            },
        )
        .await
        .map_err(|error| inventory_error(error, "update group failed"))?
        .ok_or_else(|| ApiError::not_found("group"))?;
    let mut roots = build_group_forest(groups, Some(id))?;
    roots
        .pop()
        .map(Json)
        .ok_or_else(|| ApiError::not_found("group"))
}

pub async fn handle_delete_group(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Path(id): Path<i64>,
    Query(query): Query<DeleteGroupQuery>,
) -> Result<Response, ApiError> {
    let id = validate_positive_id(id, "group id").map_err(validation_error)?;
    let scope = write_access(&current)?.scope;
    if query.force {
        let ForceDeleteOutcome {
            deleted_groups,
            ungrouped_devices,
        } = db
            .force_delete_group(scope, id)
            .await
            .map_err(|error| inventory_error(error, "force delete group failed"))?
            .ok_or_else(|| ApiError::not_found("group"))?;
        return Ok(Json(ForceDeleteGroupResponse {
            deleted_groups,
            ungrouped_devices,
        })
        .into_response());
    }

    match db
        .delete_group(scope, id)
        .await
        .map_err(|error| inventory_error(error, "delete group failed"))?
    {
        GroupDeleteOutcome::Deleted => Ok(StatusCode::NO_CONTENT.into_response()),
        GroupDeleteOutcome::NotFound => Err(ApiError::not_found("group")),
        GroupDeleteOutcome::NotEmpty => {
            Err(ApiError::conflict("group must be empty before deletion"))
        }
    }
}

pub async fn handle_add_group_devices(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Path(id): Path<i64>,
    LimitedJson(payload): LimitedJson<DeviceBatchRequest>,
) -> Result<Json<GroupBatchResponse>, ApiError> {
    let id = validate_positive_id(id, "group id").map_err(validation_error)?;
    let device_ids = payload.validate().map_err(validation_error)?;
    let scope = write_access(&current)?.scope;
    let outcome = db
        .add_devices_to_group(scope, id, &device_ids)
        .await
        .map_err(|error| inventory_error(error, "add devices to group failed"))?;
    Ok(Json(GroupBatchResponse {
        matched_devices: outcome.matched,
        changed_devices: outcome.changed,
    }))
}

pub async fn handle_remove_group_devices(
    Extension(db): Extension<Database>,
    Extension(current): Extension<CurrentUser>,
    Path(id): Path<i64>,
    LimitedJson(payload): LimitedJson<DeviceBatchRequest>,
) -> Result<Json<GroupBatchResponse>, ApiError> {
    let id = validate_positive_id(id, "group id").map_err(validation_error)?;
    let device_ids = payload.validate().map_err(validation_error)?;
    let scope = write_access(&current)?.scope;
    let outcome = db
        .remove_devices_from_group(scope, id, &device_ids)
        .await
        .map_err(|error| inventory_error(error, "remove devices from group failed"))?;
    Ok(Json(GroupBatchResponse {
        matched_devices: outcome.matched,
        changed_devices: outcome.changed,
    }))
}

fn group_node(group: GroupRecord) -> GroupTreeNode {
    GroupTreeNode {
        id: group.id,
        name: group.name,
        owner_user_id: group.owner_user_id,
        parent_group_id: group.parent_group_id,
        children: Vec::new(),
    }
}

fn build_group_forest(
    mut records: Vec<GroupRecord>,
    expected_root: Option<i64>,
) -> Result<Vec<GroupTreeNode>, ApiError> {
    if records.len() > MAX_GROUP_TREE_NODES {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "group tree exceeds the supported node limit",
        ));
    }
    if records.is_empty() {
        return if expected_root.is_some() {
            Err(ApiError::not_found("group"))
        } else {
            Ok(Vec::new())
        };
    }

    records.sort_by(compare_group_records);
    let mut by_id = HashMap::with_capacity(records.len());
    for record in records {
        if by_id.insert(record.id, record).is_some() {
            return Err(integrity_error("duplicate group id"));
        }
    }

    let mut children: HashMap<i64, Vec<i64>> = HashMap::new();
    let mut roots = Vec::new();
    for record in by_id.values() {
        if expected_root == Some(record.id) {
            if record
                .parent_group_id
                .is_some_and(|parent_id| by_id.contains_key(&parent_id))
            {
                return Err(integrity_error("subtree root participates in a cycle"));
            }
            roots.push(record.id);
            continue;
        }
        match record.parent_group_id {
            Some(parent_id) => {
                let Some(parent) = by_id.get(&parent_id) else {
                    return Err(integrity_error("orphan group parent"));
                };
                if parent.owner_user_id != record.owner_user_id {
                    return Err(integrity_error("cross-owner group parent"));
                }
                children.entry(parent_id).or_default().push(record.id);
            }
            None => roots.push(record.id),
        }
    }
    if let Some(root_id) = expected_root {
        if roots != [root_id] {
            return Err(integrity_error("invalid group subtree root"));
        }
    }

    for child_ids in children.values_mut() {
        child_ids.sort_by(|left, right| compare_group_ids(*left, *right, &by_id));
    }
    roots.sort_by(|left, right| compare_group_ids(*left, *right, &by_id));

    let mut visited = HashSet::with_capacity(by_id.len());
    let mut stack: Vec<(i64, usize)> = roots.iter().map(|id| (*id, 1)).collect();
    while let Some((id, depth)) = stack.pop() {
        if depth > MAX_GROUP_TREE_DEPTH {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "group tree exceeds the supported depth limit",
            ));
        }
        if !visited.insert(id) {
            return Err(integrity_error("group cycle"));
        }
        if let Some(child_ids) = children.get(&id) {
            stack.extend(child_ids.iter().map(|child_id| (*child_id, depth + 1)));
        }
    }
    if visited.len() != by_id.len() {
        return Err(integrity_error("unreachable group or cycle"));
    }

    let mut nodes = by_id;
    roots
        .into_iter()
        .map(|root_id| build_group_node(root_id, &mut nodes, &children))
        .collect()
}

fn build_group_node(
    id: i64,
    records: &mut HashMap<i64, GroupRecord>,
    children: &HashMap<i64, Vec<i64>>,
) -> Result<GroupTreeNode, ApiError> {
    let record = records
        .remove(&id)
        .ok_or_else(|| integrity_error("group tree references a missing node"))?;
    let child_nodes = children
        .get(&id)
        .into_iter()
        .flatten()
        .map(|child_id| build_group_node(*child_id, records, children))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(GroupTreeNode {
        id: record.id,
        name: record.name,
        owner_user_id: record.owner_user_id,
        parent_group_id: record.parent_group_id,
        children: child_nodes,
    })
}

fn compare_group_records(left: &GroupRecord, right: &GroupRecord) -> Ordering {
    left.name
        .to_ascii_lowercase()
        .cmp(&right.name.to_ascii_lowercase())
        .then_with(|| left.id.cmp(&right.id))
}

fn compare_group_ids(left: i64, right: i64, records: &HashMap<i64, GroupRecord>) -> Ordering {
    match (records.get(&left), records.get(&right)) {
        (Some(left), Some(right)) => compare_group_records(left, right),
        _ => left.cmp(&right),
    }
}

fn integrity_error(detail: &str) -> ApiError {
    hbb_common::log::error!("group tree database integrity error: {}", detail);
    ApiError::internal("group tree database integrity error")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    fn record(id: i64, name: &str, parent_group_id: Option<i64>) -> GroupRecord {
        let timestamp = DateTime::<Utc>::from_timestamp(0, 0).unwrap().naive_utc();
        GroupRecord {
            id,
            name: name.to_string(),
            owner_user_id: 7,
            parent_group_id,
            created_at: timestamp,
            updated_at: timestamp,
        }
    }

    #[test]
    fn builds_stable_three_level_tree() {
        let forest = build_group_forest(
            vec![
                record(3, "后端组", Some(2)),
                record(1, "公司", None),
                record(2, "技术部", Some(1)),
            ],
            None,
        )
        .unwrap();
        assert_eq!(forest.len(), 1);
        assert_eq!(forest[0].name, "公司");
        assert_eq!(forest[0].children[0].name, "技术部");
        assert_eq!(forest[0].children[0].children[0].name, "后端组");
    }

    #[test]
    fn rejects_orphans_and_cycles_without_recursive_overflow() {
        assert!(build_group_forest(vec![record(1, "orphan", Some(99))], None).is_err());
        assert!(
            build_group_forest(vec![record(1, "a", Some(2)), record(2, "b", Some(1))], None)
                .is_err()
        );
        assert!(build_group_forest(
            vec![record(1, "a", Some(2)), record(2, "b", Some(1))],
            Some(1)
        )
        .is_err());
    }

    #[test]
    fn subtree_keeps_original_parent_but_uses_expected_root() {
        let roots = build_group_forest(
            vec![record(2, "child", Some(1)), record(3, "leaf", Some(2))],
            Some(2),
        )
        .unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].parent_group_id, Some(1));
        assert_eq!(roots[0].children[0].id, 3);
    }

    #[test]
    fn enforces_tree_depth_before_recursive_dto_construction() {
        let at_limit = (1..=MAX_GROUP_TREE_DEPTH as i64)
            .map(|id| record(id, &format!("group-{id:03}"), (id > 1).then_some(id - 1)))
            .collect();
        assert!(build_group_forest(at_limit, None).is_ok());

        let over_limit = (1..=MAX_GROUP_TREE_DEPTH as i64 + 1)
            .map(|id| record(id, &format!("group-{id:03}"), (id > 1).then_some(id - 1)))
            .collect();
        assert!(build_group_forest(over_limit, None).is_err());
    }
}
