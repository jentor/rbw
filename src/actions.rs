use crate::prelude::*;

pub async fn register(
    email: &str,
    apikey: crate::locked::ApiKey,
) -> Result<()> {
    let (client, config) = api_client_async().await?;

    client
        .register(email, &crate::config::device_id(&config).await?, &apikey)
        .await?;

    Ok(())
}

pub async fn login(
    email: &str,
    password: crate::locked::Password,
    two_factor_token: Option<&str>,
    two_factor_provider: Option<crate::api::TwoFactorProviderType>,
) -> Result<(
    String,
    String,
    crate::api::KdfType,
    u32,
    Option<u32>,
    Option<u32>,
    String,
)> {
    let (client, config) = api_client_async().await?;
    let (kdf, iterations, memory, parallelism) =
        client.prelogin(email).await?;

    let identity = crate::identity::Identity::new(
        email,
        &password,
        kdf,
        iterations,
        memory,
        parallelism,
    )?;
    let (access_token, refresh_token, protected_key) = client
        .login(
            email,
            config.sso_id.as_deref(),
            &crate::config::device_id(&config).await?,
            &identity.master_password_hash,
            two_factor_token,
            two_factor_provider,
        )
        .await?;

    Ok((
        access_token,
        refresh_token,
        kdf,
        iterations,
        memory,
        parallelism,
        protected_key,
    ))
}

pub async fn send_two_factor_email(
    email: &str,
    sso_email_2fa_session_token: &str,
) -> Result<()> {
    let (client, config) = api_client_async().await?;
    client
        .send_email_login(
            email,
            &crate::config::device_id(&config).await?,
            sso_email_2fa_session_token,
        )
        .await
}

pub fn unlock<S: std::hash::BuildHasher>(
    email: &str,
    password: &crate::locked::Password,
    kdf: crate::api::KdfType,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
    protected_key: &str,
    protected_private_key: &str,
    protected_org_keys: &std::collections::HashMap<String, String, S>,
) -> Result<(
    crate::locked::Keys,
    std::collections::HashMap<String, crate::locked::Keys>,
)> {
    let key = derive_user_key(
        email,
        password,
        kdf,
        iterations,
        memory,
        parallelism,
        protected_key,
    )?;

    expand_user_key(key, protected_private_key, protected_org_keys)
}

pub fn derive_user_key(
    email: &str,
    password: &crate::locked::Password,
    kdf: crate::api::KdfType,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
    protected_key: &str,
) -> Result<crate::locked::Keys> {
    let identity = crate::identity::Identity::new(
        email,
        password,
        kdf,
        iterations,
        memory,
        parallelism,
    )?;

    let protected_key =
        crate::cipherstring::CipherString::new(protected_key)?;
    let key = match protected_key.decrypt_locked_symmetric(&identity.keys) {
        Ok(master_keys) => crate::locked::Keys::new(master_keys),
        Err(Error::InvalidMac) => {
            return Err(Error::IncorrectPassword {
                message: "Password is incorrect. Try again.".to_string(),
            })
        }
        Err(e) => return Err(e),
    };

    Ok(key)
}

pub fn expand_user_key<S: std::hash::BuildHasher>(
    key: crate::locked::Keys,
    protected_private_key: &str,
    protected_org_keys: &std::collections::HashMap<String, String, S>,
) -> Result<(
    crate::locked::Keys,
    std::collections::HashMap<String, crate::locked::Keys>,
)> {
    let protected_private_key =
        crate::cipherstring::CipherString::new(protected_private_key)?;
    let private_key =
        match protected_private_key.decrypt_locked_symmetric(&key) {
            Ok(private_key) => crate::locked::PrivateKey::new(private_key),
            Err(e) => return Err(e),
        };

    let mut org_keys = std::collections::HashMap::new();
    for (org_id, protected_org_key) in protected_org_keys {
        let protected_org_key =
            crate::cipherstring::CipherString::new(protected_org_key)?;
        let org_key =
            match protected_org_key.decrypt_locked_asymmetric(&private_key) {
                Ok(org_key) => crate::locked::Keys::new(org_key),
                Err(e) => return Err(e),
            };
        org_keys.insert(org_id.clone(), org_key);
    }

    Ok((key, org_keys))
}

#[cfg(test)]
mod tests {
    use rsa::pkcs8::EncodePrivateKey as _;

    use super::{derive_user_key, expand_user_key};

    fn password(s: &str) -> crate::locked::Password {
        crate::locked::Password::new(crate::locked::Vec::from_slice(
            s.as_bytes(),
        ))
    }

    #[test]
    fn derive_user_key_roundtrips_protected_key() {
        let password = password("correct horse battery staple");
        let email = "user@example.com";
        let identity = crate::identity::Identity::new(
            email,
            &password,
            crate::api::KdfType::Pbkdf2,
            600_000,
            None,
            None,
        )
        .unwrap();
        let user_key_bytes = [7_u8; 64];
        let user_key =
            crate::locked::Keys::from_bytes(&user_key_bytes).unwrap();
        let protected_key =
            crate::cipherstring::CipherString::encrypt_symmetric(
                &identity.keys,
                user_key.as_bytes(),
            )
            .unwrap()
            .to_string();

        let derived = derive_user_key(
            email,
            &password,
            crate::api::KdfType::Pbkdf2,
            600_000,
            None,
            None,
            &protected_key,
        )
        .unwrap();

        assert_eq!(derived.as_bytes(), user_key.as_bytes());
    }

    #[test]
    fn expand_user_key_unlocks_private_and_org_keys() {
        let mut rng = rand_8::thread_rng();
        let user_key_bytes = [9_u8; 64];
        let user_key =
            crate::locked::Keys::from_bytes(&user_key_bytes).unwrap();

        let rsa_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = rsa::RsaPublicKey::from(&rsa_key);
        let private_key_der = rsa_key.to_pkcs8_der().unwrap();
        let padded_private_key = pkcs7_pad(private_key_der.as_bytes(), 16);
        let protected_private_key =
            crate::cipherstring::CipherString::encrypt_symmetric(
                &user_key,
                &padded_private_key,
            )
            .unwrap()
            .to_string();

        let org_key_bytes = [3_u8; 64];
        let encrypted_org_key = public_key
            .encrypt(&mut rng, rsa::Oaep::new::<sha1::Sha1>(), &org_key_bytes)
            .unwrap();
        let mut protected_org_keys = std::collections::HashMap::new();
        protected_org_keys.insert(
            "org".to_string(),
            format!("4.{}", crate::base64::encode(&encrypted_org_key)),
        );

        let (expanded_user_key, org_keys) = expand_user_key(
            user_key,
            &protected_private_key,
            &protected_org_keys,
        )
        .unwrap();

        assert_eq!(expanded_user_key.as_bytes(), &user_key_bytes);
        assert_eq!(org_keys["org"].as_bytes(), &org_key_bytes);
    }

    fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
        let padding = block_size - (data.len() % block_size);
        let mut out = data.to_vec();
        out.extend(std::iter::repeat_n(padding as u8, padding));
        out
    }
}

pub async fn sync(
    access_token: &str,
    refresh_token: &str,
) -> Result<(
    Option<String>,
    (
        String,
        String,
        std::collections::HashMap<String, String>,
        Vec<crate::db::Entry>,
    ),
)> {
    with_exchange_refresh_token_async(
        access_token,
        refresh_token,
        |access_token| {
            let access_token = access_token.to_string();
            Box::pin(async move { sync_once(&access_token).await })
        },
    )
    .await
}

async fn sync_once(
    access_token: &str,
) -> Result<(
    String,
    String,
    std::collections::HashMap<String, String>,
    Vec<crate::db::Entry>,
)> {
    let (client, _) = api_client_async().await?;
    client.sync(access_token).await
}

pub fn add(
    access_token: &str,
    refresh_token: &str,
    name: &str,
    data: &crate::db::EntryData,
    notes: Option<&str>,
    folder_id: Option<&str>,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        add_once(access_token, name, data, notes, folder_id)
    })
}

fn add_once(
    access_token: &str,
    name: &str,
    data: &crate::db::EntryData,
    notes: Option<&str>,
    folder_id: Option<&str>,
) -> Result<()> {
    let (client, _) = api_client()?;
    client.add(access_token, name, data, notes, folder_id)?;
    Ok(())
}

pub fn edit(
    access_token: &str,
    refresh_token: &str,
    id: &str,
    org_id: Option<&str>,
    name: &str,
    data: &crate::db::EntryData,
    fields: &[crate::db::Field],
    notes: Option<&str>,
    folder_uuid: Option<&str>,
    history: &[crate::db::HistoryEntry],
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        edit_once(
            access_token,
            id,
            org_id,
            name,
            data,
            fields,
            notes,
            folder_uuid,
            history,
        )
    })
}

fn edit_once(
    access_token: &str,
    id: &str,
    org_id: Option<&str>,
    name: &str,
    data: &crate::db::EntryData,
    fields: &[crate::db::Field],
    notes: Option<&str>,
    folder_uuid: Option<&str>,
    history: &[crate::db::HistoryEntry],
) -> Result<()> {
    let (client, _) = api_client()?;
    client.edit(
        access_token,
        id,
        org_id,
        name,
        data,
        fields,
        notes,
        folder_uuid,
        history,
    )?;
    Ok(())
}

pub fn remove(
    access_token: &str,
    refresh_token: &str,
    id: &str,
) -> Result<(Option<String>, ())> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        remove_once(access_token, id)
    })
}

fn remove_once(access_token: &str, id: &str) -> Result<()> {
    let (client, _) = api_client()?;
    client.remove(access_token, id)?;
    Ok(())
}

pub fn list_folders(
    access_token: &str,
    refresh_token: &str,
) -> Result<(Option<String>, Vec<(String, String)>)> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        list_folders_once(access_token)
    })
}

fn list_folders_once(access_token: &str) -> Result<Vec<(String, String)>> {
    let (client, _) = api_client()?;
    client.folders(access_token)
}

pub fn create_folder(
    access_token: &str,
    refresh_token: &str,
    name: &str,
) -> Result<(Option<String>, String)> {
    with_exchange_refresh_token(access_token, refresh_token, |access_token| {
        create_folder_once(access_token, name)
    })
}

fn create_folder_once(access_token: &str, name: &str) -> Result<String> {
    let (client, _) = api_client()?;
    client.create_folder(access_token, name)
}

fn with_exchange_refresh_token<F, T>(
    access_token: &str,
    refresh_token: &str,
    f: F,
) -> Result<(Option<String>, T)>
where
    F: Fn(&str) -> Result<T>,
{
    match f(access_token) {
        Ok(t) => Ok((None, t)),
        Err(Error::RequestUnauthorized) => {
            let access_token = exchange_refresh_token(refresh_token)?;
            let t = f(&access_token)?;
            Ok((Some(access_token), t))
        }
        Err(e) => Err(e),
    }
}

async fn with_exchange_refresh_token_async<F, T>(
    access_token: &str,
    refresh_token: &str,
    f: F,
) -> Result<(Option<String>, T)>
where
    F: Fn(
            &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T>> + Send>,
        > + Send
        + Sync,
    T: Send,
{
    match f(access_token).await {
        Ok(t) => Ok((None, t)),
        Err(Error::RequestUnauthorized) => {
            let access_token =
                exchange_refresh_token_async(refresh_token).await?;
            let t = f(&access_token).await?;
            Ok((Some(access_token), t))
        }
        Err(e) => Err(e),
    }
}

fn exchange_refresh_token(refresh_token: &str) -> Result<String> {
    let (client, _) = api_client()?;
    client.exchange_refresh_token(refresh_token)
}

async fn exchange_refresh_token_async(refresh_token: &str) -> Result<String> {
    let (client, _) = api_client()?;
    client.exchange_refresh_token_async(refresh_token).await
}

fn api_client() -> Result<(crate::api::Client, crate::config::Config)> {
    let config = crate::config::Config::load()?;
    let client = crate::api::Client::new(
        &config.base_url(),
        &config.identity_url(),
        &config.ui_url(),
        config.client_cert_path(),
    );
    Ok((client, config))
}

async fn api_client_async(
) -> Result<(crate::api::Client, crate::config::Config)> {
    let config = crate::config::Config::load_async().await?;
    let client = crate::api::Client::new(
        &config.base_url(),
        &config.identity_url(),
        &config.ui_url(),
        config.client_cert_path(),
    );
    Ok((client, config))
}
