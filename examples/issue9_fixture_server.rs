use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use hbb_common::{anyhow::Context, ResultType};
use hbbs::{
    api::{admin_init, build_router, middleware::ApiProtectionState},
    auth::AuthState,
    config::{ApiRateLimitConfig, OidcConfig},
    database::{Database, DeviceUpdate, OwnerScope},
    DEVICE_INVALIDATION_CHANNEL_CAPACITY,
};
use http_body::Body as HttpBody;
use serde::Serialize;
use serde_json::Value;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const ROLE_HEADER: &str = "x-issue9-e2e-role";
const MAX_OBSERVED_BODY_BYTES: usize = 1024 * 1024;

#[derive(Serialize)]
struct FixtureReady {
    schema: u32,
    api_base: String,
}

#[derive(Serialize)]
struct FixtureCredentials {
    schema: u32,
    owner_username: String,
    owner_password: String,
    recipient_username: String,
    recipient_password: String,
    empty_username: String,
    empty_password: String,
    device_id: String,
    device_uuid: String,
}

#[derive(Clone, Serialize)]
struct RequestObservation {
    sequence: usize,
    role: &'static str,
    method: String,
    path: String,
    has_bearer: bool,
    has_ab_ver: bool,
    has_address_book_json: bool,
}

#[derive(Serialize)]
struct ObservationSnapshot<'a> {
    schema: u32,
    sequence: usize,
    observations: &'a [RequestObservation],
}

#[derive(Clone)]
struct RequestCapture {
    root: PathBuf,
    observations: Arc<Mutex<Vec<RequestObservation>>>,
}

impl RequestCapture {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            observations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn record(&self, mut observation: RequestObservation) -> ResultType<()> {
        let mut observations = self
            .observations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        observation.sequence = observations.len() + 1;
        observations.push(observation);
        let snapshot = ObservationSnapshot {
            schema: 1,
            sequence: observations.len(),
            observations: &observations,
        };
        write_private_json(
            &self.root.join(format!(
                "request-observations-{:06}.json",
                observations.len()
            )),
            &snapshot,
        )
    }
}

fn main() {
    if let Err(error) = tokio::runtime::Runtime::new()
        .context("无法创建 fixture runtime")
        .and_then(|runtime| runtime.block_on(run()))
    {
        let _ = error;
        eprintln!("Issue #9 fixture 启动失败");
        std::process::exit(1);
    }
}

async fn run() -> ResultType<()> {
    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .context("用法：issue9_fixture_server <私有fixture目录>")?;
    prepare_private_root(&root)?;

    let database_path = root.join("server.sqlite");
    let database_path = database_path
        .to_str()
        .context("fixture 数据库路径不是有效 UTF-8")?;
    let database = Database::new(database_path).await?;
    let protection = ApiProtectionState::new(ApiRateLimitConfig::default());

    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let owner_username = format!("issue9-owner-{}", &nonce[..12]);
    let recipient_username = format!("issue9-recipient-{}", &nonce[12..24]);
    let empty_username = format!("issue9-empty-{}", &nonce[20..32]);
    let owner_password = format!("Issue9-owner-{nonce}");
    let recipient_password = format!("Issue9-recipient-{nonce}");
    let empty_password = format!("Issue9-empty-{nonce}");
    let owner_hash = admin_init::hash_password_bounded(&protection, &owner_password).await?;
    let recipient_hash =
        admin_init::hash_password_bounded(&protection, &recipient_password).await?;
    let empty_hash = admin_init::hash_password_bounded(&protection, &empty_password).await?;
    let owner = database
        .create_user(&owner_username, &owner_hash, None, "user")
        .await?;
    database
        .create_user(&recipient_username, &recipient_hash, None, "user")
        .await?;
    database
        .create_user(&empty_username, &empty_hash, None, "user")
        .await?;

    let device_id = format!("issue9-device-{}", &nonce[24..]);
    let device_uuid = *uuid::Uuid::new_v4().as_bytes();
    database
        .insert_peer(&device_id, &device_uuid, b"issue9-fixture-public-key", "{}")
        .await?;
    database
        .update_managed_device(
            OwnerScope::All,
            &device_id,
            &DeviceUpdate {
                owner_user_id: Some(Some(owner.id)),
                alias: Some(Some("Issue 9 fixture".to_owned())),
                ..Default::default()
            },
        )
        .await?
        .context("fixture 设备应可分配给 owner")?;

    let credentials = FixtureCredentials {
        schema: 1,
        owner_username,
        owner_password,
        recipient_username,
        recipient_password,
        empty_username,
        empty_password,
        device_id,
        device_uuid: base64::encode(device_uuid),
    };
    write_private_json(&root.join("credentials.json"), &credentials)?;

    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let jwt_secret = format!("issue9-fixture-jwt-{nonce}");
    let auth_state = AuthState {
        jwt_secret,
        jwt_expiry_hours: 1,
        refresh_expiry_days: 1,
    };
    let (device_tx, _device_rx) = tokio::sync::mpsc::channel(DEVICE_INVALIDATION_CHANNEL_CAPACITY);
    let capture = RequestCapture::new(root.clone());
    let app = build_router(database, auth_state, OidcConfig::default(), device_tx).layer(
        axum::middleware::from_fn(move |request, next| {
            observe_request(capture.clone(), request, next)
        }),
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = axum::Server::from_tcp(listener)?
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        });
    let server_task = tokio::spawn(server);

    let api_base = format!("http://{address}");
    write_private_json(
        &root.join("ready.json"),
        &FixtureReady {
            schema: 1,
            api_base: api_base.clone(),
        },
    )?;
    println!("ISSUE9_FIXTURE_READY {api_base}");

    let stop_path = root.join("stop");
    while !stop_path.exists() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = shutdown_tx.send(());
    server_task.await??;
    Ok(())
}

async fn observe_request(
    capture: RequestCapture,
    request: Request<Body>,
    next: Next<Body>,
) -> Response {
    let role = request
        .headers()
        .get(ROLE_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(known_role);
    let Some(role) = role else {
        return next.run(request).await;
    };

    let method = request.method().to_string();
    let path = request.uri().path().to_owned();
    let has_bearer = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let mut parts = value.split_ascii_whitespace();
            parts
                .next()
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case("bearer"))
                && parts
                    .next()
                    .is_some_and(|credential| !credential.is_empty())
                && parts.next().is_none()
        });
    let query_has_ab_ver = request.uri().query().is_some_and(|query| {
        query.split('&').any(|pair| {
            pair.split_once('=')
                .map(|(name, _)| name == "ab_ver")
                .unwrap_or(pair == "ab_ver")
        })
    });
    let inspect_json_body =
        matches!(role, "service" | "ui-event-producer") && path == "/api/sysinfo";
    let (request, body_has_ab_ver, body_has_address_book_json) = if inspect_json_body {
        match inspect_body_keys(request).await {
            Ok(result) => result,
            Err(response) => return response,
        }
    } else {
        (request, false, false)
    };
    if capture
        .record(RequestObservation {
            sequence: 0,
            role,
            method,
            path,
            has_bearer,
            has_ab_ver: query_has_ab_ver || body_has_ab_ver,
            has_address_book_json: body_has_address_book_json,
        })
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "fixture request observation failed",
        )
            .into_response();
    }
    next.run(request).await
}

async fn inspect_body_keys(
    request: Request<Body>,
) -> Result<(Request<Body>, bool, bool), Response> {
    let (parts, mut body) = request.into_parts();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "fixture could not inspect request body",
            )
                .into_response()
        })?;
        if bytes.len().saturating_add(chunk.as_ref().len()) > MAX_OBSERVED_BODY_BYTES {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                "fixture observation body limit exceeded",
            )
                .into_response());
        }
        bytes.extend_from_slice(chunk.as_ref());
    }
    let json = serde_json::from_slice::<Value>(&bytes).ok();
    let has_ab_ver = json
        .as_ref()
        .and_then(Value::as_object)
        .is_some_and(|object| object.contains_key("ab_ver"));
    let has_address_book_json = json
        .as_ref()
        .and_then(Value::as_object)
        .is_some_and(|object| object.contains_key("address_book_json"));
    Ok((
        Request::from_parts(parts, Body::from(bytes)),
        has_ab_ver,
        has_address_book_json,
    ))
}

fn known_role(value: &str) -> Option<&'static str> {
    match value {
        "service" => Some("service"),
        "ui-event-producer" => Some("ui-event-producer"),
        _ => None,
    }
}

fn prepare_private_root(root: &Path) -> ResultType<()> {
    fs::create_dir_all(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_private_json(path: &Path, value: &impl Serialize) -> ResultType<()> {
    let bytes = serde_json::to_vec(value)?;
    let directory = path.parent().context("私有 JSON 路径缺少父目录")?;
    let leaf = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("私有 JSON 文件名无效")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temporary = directory.join(format!(".{leaf}.{}.{nonce}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> ResultType<()> {
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
