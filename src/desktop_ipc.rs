use std::io;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use rsa::pkcs8::EncodePublicKey as _;
use sha2::Digest as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use zeroize::Zeroize as _;

const HOST_NAME: &str = "com.8bit.bitwarden";
const BITWARDEN_DESKTOP_BUNDLE_ID: &str = "com.bitwarden.desktop";
const BITWARDEN_DESKTOP_TEAM_ID: &str = "LTZ2PFU5D6";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(60);
const MESSAGE_VALID_WINDOW_MS: i64 = 10_000;
const MAX_NATIVE_MESSAGE_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Identity {
    profile: String,
    server_name: String,
    email: String,
    user_id: String,
}

impl Identity {
    pub fn new(
        profile: impl Into<String>,
        server_name: impl Into<String>,
        email: impl Into<String>,
        user_id: impl Into<String>,
    ) -> Self {
        Self {
            profile: profile.into(),
            server_name: server_name.into(),
            email: email.into(),
            user_id: user_id.into(),
        }
    }

    pub fn app_id(&self) -> String {
        let material = format!(
            "{}\u{1f}{}\u{1f}{}",
            self.profile, self.server_name, self.email
        );
        let digest = sha2::Sha256::digest(material.as_bytes());
        format!(
            "rbw-cli.{}.{}",
            sanitize_profile(&self.profile),
            crate::base64::encode_url_safe_no_pad(digest)
        )
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(
        "desktop IPC biometric unlock is not supported on this platform"
    )]
    UnsupportedPlatform,

    #[error("Bitwarden Desktop IPC is unavailable: {message}")]
    Unavailable { message: String },

    #[error("Bitwarden Desktop biometric unlock was cancelled")]
    Canceled,

    #[error("Bitwarden Desktop biometric unlock was denied")]
    Denied,

    #[error("Bitwarden Desktop IPC protocol error: {message}")]
    Protocol { message: String },
}

pub type Result<T> = std::result::Result<T, Error>;

pub async fn unlock_with_biometrics(
    identity: &Identity,
    pinentry: &str,
    environment: &crate::protocol::Environment,
) -> Result<crate::locked::Keys> {
    #[cfg(target_os = "macos")]
    {
        let proxy_path = discover_proxy_path().await?;
        let mut session =
            Session::spawn(proxy_path, identity.clone()).await?;
        session.unlock_with_biometrics(pinentry, environment).await
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (identity, pinentry, environment);
        Err(Error::UnsupportedPlatform)
    }
}

pub fn identity_from_access_token(
    profile: impl Into<String>,
    server_name: impl Into<String>,
    email: impl Into<String>,
    access_token: &str,
) -> Result<Identity> {
    let claims = decode_access_token_claims(access_token)?;
    Ok(Identity::new(profile, server_name, email, claims.sub))
}

#[derive(serde::Deserialize)]
struct AccessTokenClaims {
    sub: String,
}

fn decode_access_token_claims(
    access_token: &str,
) -> Result<AccessTokenClaims> {
    let payload =
        access_token
            .split('.')
            .nth(1)
            .ok_or_else(|| Error::Protocol {
                message: "access token was not a JWT".to_string(),
            })?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| Error::Protocol {
            message: format!("failed to decode JWT payload: {e}"),
        })?;
    serde_json::from_slice(&payload).map_err(|e| Error::Protocol {
        message: format!("failed to parse JWT payload: {e}"),
    })
}

#[cfg(target_os = "macos")]
#[derive(serde::Deserialize)]
struct Manifest {
    path: PathBuf,
}

#[cfg(target_os = "macos")]
async fn discover_proxy_path() -> Result<PathBuf> {
    for path in manifest_paths() {
        match tokio::fs::read_to_string(&path).await {
            Ok(contents) => {
                let manifest: Manifest = serde_json::from_str(&contents)
                    .map_err(|e| Error::Protocol {
                        message: format!(
                            "failed to parse {} manifest at {}: {e}",
                            HOST_NAME,
                            path.display()
                        ),
                    })?;
                if manifest.path.exists() {
                    if let Ok(path) = validate_proxy_path(manifest.path).await
                    {
                        return Ok(path);
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(Error::Unavailable {
                    message: format!(
                        "failed to read native messaging manifest {}: {e}",
                        path.display()
                    ),
                })
            }
        }
    }

    let fallback_paths = [
        "/Applications/Bitwarden.app/Contents/MacOS/desktop_proxy",
        "~/Applications/Bitwarden.app/Contents/MacOS/desktop_proxy",
    ];
    for path in fallback_paths {
        let path = expand_home(path);
        if path.exists() {
            if let Ok(path) = validate_proxy_path(path).await {
                return Ok(path);
            }
        }
    }

    Err(Error::Unavailable {
        message: "could not find Bitwarden Desktop native messaging host"
            .to_string(),
    })
}

#[cfg(target_os = "macos")]
async fn validate_proxy_path(path: PathBuf) -> Result<PathBuf> {
    let path = tokio::fs::canonicalize(&path).await.map_err(|e| {
        Error::Unavailable {
            message: format!(
                "failed to canonicalize desktop proxy {}: {e}",
                path.display()
            ),
        }
    })?;
    if path.file_name().and_then(std::ffi::OsStr::to_str)
        != Some("desktop_proxy")
    {
        return Err(Error::Unavailable {
            message: format!(
                "refusing unexpected desktop proxy path {}",
                path.display()
            ),
        });
    }
    verify_proxy_signature(&path).await?;
    Ok(path)
}

#[cfg(target_os = "macos")]
async fn verify_proxy_signature(path: &std::path::Path) -> Result<()> {
    let output = tokio::process::Command::new("codesign")
        .args(["-dv", "--verbose=4"])
        .arg(path)
        .output()
        .await
        .map_err(|e| Error::Unavailable {
            message: format!(
                "failed to inspect desktop proxy signature {}: {e}",
                path.display()
            ),
        })?;
    if !output.status.success() {
        return Err(Error::Unavailable {
            message: format!(
                "desktop proxy signature verification failed for {}",
                path.display()
            ),
        });
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let identifier = stderr
        .lines()
        .find_map(|line| line.strip_prefix("Identifier="));
    let team_id = stderr
        .lines()
        .find_map(|line| line.strip_prefix("TeamIdentifier="));
    if identifier != Some(BITWARDEN_DESKTOP_BUNDLE_ID)
        || team_id != Some(BITWARDEN_DESKTOP_TEAM_ID)
    {
        return Err(Error::Unavailable {
            message: format!(
                "desktop proxy {} is not signed as official Bitwarden Desktop",
                path.display()
            ),
        });
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn manifest_paths() -> Vec<PathBuf> {
    let home = home_dir();
    [
        "Library/Application Support/Mozilla/NativeMessagingHosts",
        "Library/Application Support/Google/Chrome/NativeMessagingHosts",
        "Library/Application Support/Google/Chrome Beta/NativeMessagingHosts",
        "Library/Application Support/Google/Chrome Dev/NativeMessagingHosts",
        "Library/Application Support/Google/Chrome Canary/NativeMessagingHosts",
        "Library/Application Support/Chromium/NativeMessagingHosts",
        "Library/Application Support/Microsoft Edge/NativeMessagingHosts",
        "Library/Application Support/Microsoft Edge Beta/NativeMessagingHosts",
        "Library/Application Support/Microsoft Edge Dev/NativeMessagingHosts",
        "Library/Application Support/Microsoft Edge Canary/NativeMessagingHosts",
        "Library/Application Support/Vivaldi/NativeMessagingHosts",
        "Library/Application Support/Zen/NativeMessagingHosts",
        "Library/Application Support/net.imput.helium/NativeMessagingHosts",
    ]
    .into_iter()
    .map(|root| home.join(root).join(format!("{HOST_NAME}.json")))
    .collect()
}

#[cfg(target_os = "macos")]
fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

#[cfg(target_os = "macos")]
fn expand_home(path: &str) -> PathBuf {
    if let Some(path) = path.strip_prefix("~/") {
        home_dir().join(path)
    } else {
        PathBuf::from(path)
    }
}

fn sanitize_profile(profile: &str) -> String {
    profile
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(target_os = "macos")]
struct Session {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,
    identity: Identity,
    app_id: String,
    private_key: rsa::RsaPrivateKey,
    public_key_der: Vec<u8>,
    shared_secret: Option<crate::locked::Keys>,
    next_message_id: u64,
}

#[cfg(target_os = "macos")]
impl Session {
    async fn spawn(path: PathBuf, identity: Identity) -> Result<Self> {
        let mut child = tokio::process::Command::new(&path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| Error::Unavailable {
                message: format!(
                    "failed to launch desktop proxy {}: {e}",
                    path.display()
                ),
            })?;

        let stdin = child.stdin.take().ok_or_else(|| Error::Unavailable {
            message: "desktop proxy stdin was unavailable".to_string(),
        })?;
        let stdout =
            child.stdout.take().ok_or_else(|| Error::Unavailable {
                message: "desktop proxy stdout was unavailable".to_string(),
            })?;

        let mut rng = rand_8::rngs::OsRng;
        let private_key =
            rsa::RsaPrivateKey::new(&mut rng, 2048).map_err(|e| {
                Error::Protocol {
                    message: format!("failed to generate RSA keypair: {e}"),
                }
            })?;
        let public_key_der = private_key
            .to_public_key()
            .to_public_key_der()
            .map_err(|e| Error::Protocol {
                message: format!("failed to encode RSA public key: {e}"),
            })?
            .as_bytes()
            .to_vec();

        let mut session = Self {
            child,
            stdin,
            stdout,
            app_id: identity.app_id(),
            identity,
            private_key,
            public_key_der,
            shared_secret: None,
            next_message_id: 1,
        };
        session.wait_for_connected().await?;
        session.setup_secure_channel().await?;
        Ok(session)
    }

    async fn unlock_with_biometrics(
        &mut self,
        pinentry: &str,
        environment: &crate::protocol::Environment,
    ) -> Result<crate::locked::Keys> {
        let message_id = self.next_message_id();
        self.send_encrypted(
            &Message::command(
                "unlockWithBiometricsForUser",
                message_id,
                self.identity.user_id().to_string(),
            ),
            Some(message_id),
        )
        .await?;

        loop {
            let outer = self.read_message().await?;
            match outer.command.as_deref() {
                Some("verifyDesktopIPCFingerprint") => {
                    let accepted = confirm_fingerprint(
                        pinentry,
                        environment,
                        &self.fingerprint()?,
                    )
                    .await
                    .map_err(|e| Error::Unavailable {
                        message: format!(
                            "failed to confirm Bitwarden Desktop fingerprint: {e}"
                        ),
                    })?;
                    let command = if accepted {
                        "verifiedDesktopIPCFingerprint"
                    } else {
                        "rejectedDesktopIPCFingerprint"
                    };
                    self.send_outer(&OuterMessage::command(
                        command,
                        self.app_id.clone(),
                    ))
                    .await?;
                    if !accepted {
                        return Err(Error::Denied);
                    }
                }
                Some("disconnected") => {
                    return Err(Error::Unavailable {
                        message: "desktop proxy disconnected".to_string(),
                    })
                }
                _ => {
                    let message = self
                        .decode_response_message(outer, Some(message_id))
                        .await?;
                    if message.command != "unlockWithBiometricsForUser" {
                        continue;
                    }
                    if !message.response.unwrap_or(false) {
                        return Err(Error::Denied);
                    }
                    let user_key_b64 =
                        message.user_key_b64.ok_or_else(|| Error::Protocol {
                            message:
                                "desktop unlock response did not include a user key"
                                    .to_string(),
                        })?;
                    let mut user_key = crate::base64::decode(user_key_b64)
                        .map_err(|e| Error::Protocol {
                            message: format!(
                                "failed to decode desktop user key: {e}"
                            ),
                        })?;
                    let keys = crate::locked::Keys::from_bytes(&user_key)
                        .map_err(|e| Error::Protocol {
                            message: format!(
                                "desktop returned an invalid user key: {e}"
                            ),
                        });
                    user_key.zeroize();
                    return keys;
                }
            }
        }
    }

    async fn wait_for_connected(&mut self) -> Result<()> {
        loop {
            let outer = tokio::time::timeout(
                CONNECT_TIMEOUT,
                read_native_message(&mut self.stdout),
            )
            .await
            .map_err(|_| Error::Unavailable {
                message: "timed out waiting for desktop proxy connection"
                    .to_string(),
            })?
            .map_err(native_message_error)?;
            if outer.command.as_deref() == Some("connected") {
                return Ok(());
            }
            if outer.command.as_deref() == Some("disconnected") {
                return Err(Error::Unavailable {
                    message:
                        "desktop proxy could not connect to Bitwarden Desktop"
                            .to_string(),
                });
            }
        }
    }

    async fn setup_secure_channel(&mut self) -> Result<()> {
        let message_id = self.next_message_id();
        self.send_outer(&OuterMessage::setup(
            self.app_id.clone(),
            Message::setup_encryption(
                message_id,
                self.identity.user_id().to_string(),
                crate::base64::encode(&self.public_key_der),
            ),
        ))
        .await?;

        loop {
            let outer = self.read_message().await?;
            match outer.command.as_deref() {
                Some("setupEncryption") => {
                    if outer.app_id.as_deref() != Some(&self.app_id) {
                        continue;
                    }
                    let secret_b64 = outer.shared_secret.as_deref().ok_or_else(
                        || Error::Protocol {
                            message:
                                "desktop setupEncryption response was missing a shared secret"
                                    .to_string(),
                        },
                    )?;
                    let mut secret =
                        crate::base64::decode(secret_b64).map_err(|e| {
                            Error::Protocol {
                                message: format!(
                                    "failed to decode desktop shared secret: {e}"
                                ),
                            }
                        })?;
                    secret = self
                        .private_key
                        .decrypt(rsa::Oaep::new::<sha1::Sha1>(), &secret)
                        .map_err(|e| Error::Protocol {
                            message: format!(
                                "failed to decrypt desktop shared secret: {e}"
                            ),
                        })?;
                    let shared_secret = crate::locked::Keys::from_bytes(&secret)
                        .map_err(|e| Error::Protocol {
                            message: format!(
                                "desktop shared secret had invalid length: {e}"
                            ),
                        });
                    secret.zeroize();
                    self.shared_secret = Some(
                        shared_secret?
                    );
                    return Ok(());
                }
                Some("wrongUserId") => {
                    return Err(Error::Unavailable {
                        message: format!(
                            "Bitwarden Desktop is not logged into the same account as rbw ({})",
                            self.identity.email()
                        ),
                    })
                }
                Some("disconnected") => {
                    return Err(Error::Unavailable {
                        message: "desktop proxy disconnected".to_string(),
                    })
                }
                _ => {}
            }
        }
    }

    async fn send_outer(&mut self, outer: &OuterMessage) -> Result<()> {
        write_native_message(&mut self.stdin, outer)
            .await
            .map_err(native_message_error)
    }

    async fn send_encrypted(
        &mut self,
        message: &Message,
        message_id: Option<u64>,
    ) -> Result<()> {
        let secret =
            self.shared_secret.as_ref().ok_or_else(|| Error::Protocol {
                message: "desktop IPC secure channel is not initialized"
                    .to_string(),
            })?;
        let plaintext =
            serde_json::to_vec(message).map_err(|e| Error::Protocol {
                message: format!("failed to encode desktop IPC payload: {e}"),
            })?;
        let cipher = crate::cipherstring::CipherString::encrypt_symmetric(
            secret, &plaintext,
        )
        .map_err(|e| Error::Protocol {
            message: format!("failed to encrypt desktop IPC payload: {e}"),
        })?;
        let outer = OuterMessage::encrypted(
            self.app_id.clone(),
            LegacyEncString::from_cipherstring(cipher)?,
            message_id,
        );
        self.send_outer(&outer).await
    }

    async fn read_message(&mut self) -> Result<OuterMessage> {
        tokio::time::timeout(
            MESSAGE_TIMEOUT,
            read_native_message(&mut self.stdout),
        )
        .await
        .map_err(|_| Error::Unavailable {
            message: "timed out waiting for Bitwarden Desktop IPC response"
                .to_string(),
        })?
        .map_err(native_message_error)
    }

    async fn decode_response_message(
        &mut self,
        outer: OuterMessage,
        expected_message_id: Option<u64>,
    ) -> Result<ResponseMessage> {
        if outer.app_id.as_deref() != Some(&self.app_id) {
            return Err(Error::Protocol {
                message: "desktop IPC response appId did not match request"
                    .to_string(),
            });
        }
        let encrypted = outer.message.ok_or_else(|| Error::Protocol {
            message: "desktop IPC response did not include a message"
                .to_string(),
        })?;
        let encrypted = match encrypted {
            MessageEnvelope::Encrypted(encrypted) => encrypted,
            MessageEnvelope::Plain(_) => {
                return Err(Error::Protocol {
                    message:
                        "desktop IPC response unexpectedly contained a plain message"
                            .to_string(),
                })
            }
        };
        let secret =
            self.shared_secret.as_ref().ok_or_else(|| Error::Protocol {
                message: "desktop IPC secure channel is not initialized"
                    .to_string(),
            })?;
        let plaintext =
            encrypted.decrypt(secret).map_err(|e| Error::Protocol {
                message: format!(
                    "failed to decrypt desktop IPC message: {e}"
                ),
            })?;
        let response: ResponseMessage = serde_json::from_slice(&plaintext)
            .map_err(|e| Error::Protocol {
                message: format!("failed to parse desktop IPC message: {e}"),
            })?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| Error::Protocol {
                message: format!("system clock is invalid: {e}"),
            })?
            .as_millis() as i64;
        if (response.timestamp as i64 - now).abs() > MESSAGE_VALID_WINDOW_MS {
            return Err(Error::Protocol {
                message: "desktop IPC response timestamp was outside the valid window"
                    .to_string(),
            });
        }
        if let Some(expected_message_id) = expected_message_id {
            if response.message_id != expected_message_id {
                return Err(Error::Protocol {
                    message: format!(
                        "desktop IPC response message id {} did not match {}",
                        response.message_id, expected_message_id
                    ),
                });
            }
        }

        Ok(response)
    }

    fn next_message_id(&mut self) -> u64 {
        let message_id = self.next_message_id;
        self.next_message_id += 1;
        message_id
    }

    fn fingerprint(&self) -> Result<String> {
        let key_fingerprint = sha2::Sha256::digest(&self.public_key_der);
        let hkdf =
            hkdf::Hkdf::<sha2::Sha256>::new(None, key_fingerprint.as_slice());
        let mut okm = [0_u8; 32];
        hkdf.expand(self.app_id.as_bytes(), &mut okm).map_err(|_| {
            Error::Protocol {
                message: "failed to derive desktop IPC fingerprint material"
                    .to_string(),
            }
        })?;
        Ok(hash_phrase(&okm).join("-"))
    }
}

#[cfg(target_os = "macos")]
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

#[cfg(target_os = "macos")]
#[derive(serde::Serialize)]
struct OuterMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<String>,
    #[serde(rename = "appId", skip_serializing_if = "Option::is_none")]
    app_id: Option<String>,
    #[serde(rename = "messageId", skip_serializing_if = "Option::is_none")]
    message_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<MessageEnvelope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shared_secret: Option<String>,
}

#[cfg(target_os = "macos")]
impl OuterMessage {
    fn setup(app_id: String, message: Message) -> Self {
        Self {
            command: None,
            app_id: Some(app_id),
            message_id: None,
            message: Some(MessageEnvelope::Plain(message)),
            shared_secret: None,
        }
    }

    fn encrypted(
        app_id: String,
        message: LegacyEncString,
        message_id: Option<u64>,
    ) -> Self {
        Self {
            command: None,
            app_id: Some(app_id),
            message_id: message_id.map(|value| value as i64),
            message: Some(MessageEnvelope::Encrypted(message)),
            shared_secret: None,
        }
    }

    fn command(command: &str, app_id: String) -> Self {
        Self {
            command: Some(command.to_string()),
            app_id: Some(app_id),
            message_id: None,
            message: None,
            shared_secret: None,
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(serde::Serialize)]
#[serde(untagged)]
enum MessageEnvelope {
    Plain(Message),
    Encrypted(LegacyEncString),
}

#[cfg(target_os = "macos")]
#[derive(serde::Deserialize)]
struct OuterMessageWire {
    command: Option<String>,
    #[serde(rename = "appId")]
    app_id: Option<String>,
    #[serde(rename = "messageId")]
    message_id: Option<i64>,
    message: Option<LegacyEncString>,
    #[serde(rename = "sharedSecret")]
    shared_secret: Option<String>,
}

#[cfg(target_os = "macos")]
impl From<OuterMessageWire> for OuterMessage {
    fn from(value: OuterMessageWire) -> Self {
        Self {
            command: value.command,
            app_id: value.app_id,
            message_id: value.message_id,
            message: value.message.map(MessageEnvelope::Encrypted),
            shared_secret: value.shared_secret,
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(serde::Serialize)]
struct Message {
    command: String,
    #[serde(rename = "messageId")]
    message_id: u64,
    #[serde(rename = "userId")]
    user_id: String,
    timestamp: u64,
    #[serde(rename = "publicKey", skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
}

#[cfg(target_os = "macos")]
impl Message {
    fn setup_encryption(
        message_id: u64,
        user_id: String,
        public_key: String,
    ) -> Self {
        Self {
            command: "setupEncryption".to_string(),
            message_id,
            user_id,
            timestamp: timestamp_ms(),
            public_key: Some(public_key),
        }
    }

    fn command(command: &str, message_id: u64, user_id: String) -> Self {
        Self {
            command: command.to_string(),
            message_id,
            user_id,
            timestamp: timestamp_ms(),
            public_key: None,
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(serde::Deserialize)]
struct ResponseMessage {
    command: String,
    timestamp: u64,
    #[serde(rename = "messageId")]
    message_id: u64,
    response: Option<bool>,
    #[serde(rename = "userKeyB64")]
    user_key_b64: Option<String>,
}

#[cfg(target_os = "macos")]
#[derive(serde::Serialize, serde::Deserialize)]
struct LegacyEncString {
    #[serde(rename = "encryptedString")]
    encrypted_string: String,
    #[serde(rename = "encryptionType")]
    encryption_type: u8,
    data: String,
    iv: String,
    mac: Option<String>,
}

#[cfg(target_os = "macos")]
impl LegacyEncString {
    fn from_cipherstring(
        cipher: crate::cipherstring::CipherString,
    ) -> Result<Self> {
        let encrypted_string = cipher.to_string();
        let (ty, rest) =
            encrypted_string.split_once('.').ok_or_else(|| {
                Error::Protocol {
                    message:
                        "failed to serialize encrypted desktop IPC message"
                            .to_string(),
                }
            })?;
        let encryption_type =
            ty.parse::<u8>().map_err(|e| Error::Protocol {
                message: format!("invalid encrypted desktop IPC type: {e}"),
            })?;
        let mut parts = rest.split('|');
        let iv = parts
            .next()
            .ok_or_else(|| Error::Protocol {
                message: "encrypted desktop IPC message missing iv"
                    .to_string(),
            })?
            .to_string();
        let data = parts
            .next()
            .ok_or_else(|| Error::Protocol {
                message: "encrypted desktop IPC message missing ciphertext"
                    .to_string(),
            })?
            .to_string();
        let mac = parts.next().map(std::string::ToString::to_string);
        Ok(Self {
            encrypted_string,
            encryption_type,
            data,
            iv,
            mac,
        })
    }

    fn decrypt(
        &self,
        key: &crate::locked::Keys,
    ) -> crate::error::Result<Vec<u8>> {
        crate::cipherstring::CipherString::new(&self.encrypted_string)?
            .decrypt_symmetric(key, None)
    }
}

#[cfg(target_os = "macos")]
async fn write_native_message<W, T>(
    writer: &mut W,
    value: &T,
) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let payload = serde_json::to_vec(value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    writer
        .write_all(&(payload.len() as u32).to_le_bytes())
        .await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(target_os = "macos")]
async fn read_native_message<R>(reader: &mut R) -> io::Result<OuterMessage>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header).await?;
    let len = u32::from_le_bytes(header) as usize;
    if len > MAX_NATIVE_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("native message exceeded maximum size: {len} bytes"),
        ));
    }
    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload).await?;
    let wire: OuterMessageWire = serde_json::from_slice(&payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(wire.into())
}

#[cfg(target_os = "macos")]
fn native_message_error(err: io::Error) -> Error {
    match err.kind() {
        io::ErrorKind::InvalidData => Error::Protocol {
            message: err.to_string(),
        },
        _ => Error::Unavailable {
            message: err.to_string(),
        },
    }
}

#[cfg(target_os = "macos")]
async fn confirm_fingerprint(
    pinentry: &str,
    environment: &crate::protocol::Environment,
    fingerprint: &str,
) -> anyhow::Result<bool> {
    crate::pinentry::confirm(
        pinentry,
        "Trust Bitwarden Desktop",
        &format!(
            "Bitwarden Desktop asked rbw to verify a local IPC fingerprint before biometric unlock.\n\nFingerprint:\n{fingerprint}\n\nApprove this request to trust the current desktop session."
        ),
        environment,
    )
    .await
    .map_err(anyhow::Error::new)
}

#[cfg(target_os = "macos")]
fn timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn hash_phrase(hash: &[u8]) -> Vec<&'static str> {
    let entropy_per_word = (crate::wordlist::EFF_LONG.len() as f64).log2();
    let mut words = (64_f64 / entropy_per_word).ceil() as usize;
    let mut hash_number = hash.to_vec();
    let mut phrase = Vec::new();
    while words > 0 {
        let (quotient, remainder) =
            div_mod_be(&hash_number, crate::wordlist::EFF_LONG.len() as u32);
        phrase.push(crate::wordlist::EFF_LONG[remainder as usize]);
        hash_number = quotient;
        words -= 1;
    }
    phrase
}

fn div_mod_be(number: &[u8], divisor: u32) -> (Vec<u8>, u32) {
    let mut remainder = 0_u32;
    let mut quotient = Vec::with_capacity(number.len());
    for &byte in number {
        let value = (remainder << 8) | u32::from(byte);
        let digit = value / divisor;
        remainder = value % divisor;
        if !quotient.is_empty() || digit != 0 {
            quotient.push(digit as u8);
        }
    }
    (quotient, remainder)
}

#[cfg(test)]
mod tests {
    use super::{
        div_mod_be, hash_phrase, identity_from_access_token, Identity,
    };

    #[test]
    fn app_id_is_stable_for_same_identity() {
        let first = Identity::new(
            "rbw-work",
            "default",
            "user@example.com",
            "user-id",
        );
        let second = Identity::new(
            "rbw-work",
            "default",
            "user@example.com",
            "other-user-id",
        );
        assert_eq!(first.app_id(), second.app_id());
    }

    #[test]
    fn app_id_changes_when_identity_changes() {
        let first =
            Identity::new("rbw", "default", "user@example.com", "user-id");
        let second = Identity::new(
            "rbw",
            "https://selfhosted.example.com",
            "user@example.com",
            "user-id",
        );
        assert_ne!(first.app_id(), second.app_id());
    }

    #[test]
    fn extracts_user_id_from_access_token() {
        let header =
            crate::base64::encode_url_safe_no_pad(br#"{"alg":"none"}"#);
        let payload = crate::base64::encode_url_safe_no_pad(
            br#"{"sub":"0f4d5c39-3f8d-4ef2-84af-1783d4280c38"}"#,
        );
        let token = format!("{header}.{payload}.sig");
        let identity = identity_from_access_token(
            "rbw",
            "default",
            "user@example.com",
            &token,
        )
        .unwrap();
        assert_eq!(
            identity.user_id(),
            "0f4d5c39-3f8d-4ef2-84af-1783d4280c38"
        );
    }

    #[test]
    fn div_mod_handles_big_endian_numbers() {
        let (quotient, remainder) = div_mod_be(&[0x01, 0x00], 10);
        assert_eq!(quotient, vec![25]);
        assert_eq!(remainder, 6);
    }

    #[test]
    fn hash_phrase_produces_five_words() {
        let phrase = hash_phrase(&[7_u8; 32]);
        assert_eq!(phrase.len(), 5);
    }
}
