use std::borrow::Cow;
extern crate sequoia_openpgp as openpgp;
use openpgp::cert::CertParser;
use openpgp::parse::Parse;
use zbase32;

use futures::future::join_all;
use hyper_tls::HttpsConnector;
use serde::{Deserialize, Serialize};
use std::error::Error;

use hyper::{Body, Client, Request, Response};

#[derive(Deserialize, Debug)]
pub struct Req<'a> {
    pub email: &'a str,
}

#[derive(Debug)]
pub struct Parts<'a> {
    pub email: &'a str,
    advanced_key_url: String,
    advanced_policy_url: String,
    direct_key_url: String,
    direct_policy_url: String,
}

impl Req<'_> {
    fn parts(&self) -> Vec<&str> {
        self.email.split('@').collect::<Vec<&str>>()
    }

    fn encoded_part(bytes: &[u8]) -> String {
        let mut m = sha1::Sha1::new();
        m.update(bytes);
        let digest = m.digest();
        let bytes = digest.bytes();
        zbase32::encode_full_bytes(&bytes)
    }

    pub fn parse(&self) -> Parts {
        let parts = self.parts();
        let local = parts[0];
        let encoded_local = Self::encoded_part(local.to_lowercase().as_bytes());
        let domain = parts[1];
        Parts {
            email: self.email,
            advanced_key_url: format!(
                "https://openpgpkey.{}/.well-known/openpgpkey/{}/hu/{}?l={}",
                domain, domain, encoded_local, local
            ),
            advanced_policy_url: format!(
                "https://openpgpkey.{}/.well-known/openpgpkey/{}/policy",
                domain, domain
            ),
            direct_key_url: format!(
                "https://{}/.well-known/openpgpkey/hu/{}?l={}",
                domain, encoded_local, local
            ),
            direct_policy_url: format!("https://{}/.well-known/openpgpkey/policy", domain),
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_parsing() {
        let req = crate::Req {
            email: "ESchwartz@archlinux.org",
        };
        let parts = req.parse();
        assert_eq!(parts.advanced_key_url, "https://openpgpkey.archlinux.org/.well-known/openpgpkey/archlinux.org/hu/ycx3iaqih9tzkfk7dp8jo9xrdepu5m8u?l=ESchwartz");
        assert_eq!(
            parts.advanced_policy_url,
            "https://openpgpkey.archlinux.org/.well-known/openpgpkey/archlinux.org/policy"
        );
        assert_eq!(parts.direct_key_url, "https://archlinux.org/.well-known/openpgpkey/hu/ycx3iaqih9tzkfk7dp8jo9xrdepu5m8u?l=ESchwartz");
        assert_eq!(
            parts.direct_policy_url,
            "https://archlinux.org/.well-known/openpgpkey/policy"
        );
    }
}

#[derive(Debug, Serialize)]
struct KeyUrlInfo {
    url: String,
    cors: Option<String>,
    status: u16,
    keys: Vec<KeyInfo>,
}

impl KeyUrlInfo {
    async fn find_key(url: String, res: Response<Body>) -> Result<KeyUrlInfo, Box<dyn Error>> {
        let status = res.status();
        if status != 200 {
            return Ok(KeyUrlInfo {
                url,
                cors: None,
                status: status.as_u16(),
                keys: Vec::new(),
            });
        }

        let cors = res
            .headers()
            .get("Access-Control-Allow-Origin")
            .map(|h| h.to_str().ok().unwrap_or("").to_owned());

        let bytes = hyper::body::to_bytes(res.into_body()).await?;

        let parser = CertParser::from_bytes(&bytes)?;

        let mut keys = Vec::new();
        for cert in parser {
            match cert {
                Ok(cert) => {
                    keys.push(KeyInfo {
                        userids: cert
                            .userids()
                            .map(|u| String::from_utf8_lossy(u.value()).into_owned())
                            .collect::<Vec<String>>(),
                        fpr: cert.fingerprint().to_string(),
                    });
                }
                Err(_) => (),
            }
        }

        Ok(KeyUrlInfo {
            url,
            cors,
            status: status.as_u16(),
            keys,
        })
    }
}

#[derive(Debug, Serialize)]
struct KeyInfo {
    userids: Vec<String>,
    fpr: String,
}

impl KeyInfo {
    fn get_first_matching_uid(&self, email: &str) -> Option<&String> {
        self.userids
            .iter()
            .find(|u| *u == email || u.contains(&format!("<{}>", email)))
    }
}

#[derive(Debug, Serialize)]
struct PolicyInfo {
    url: String,
    status: u16,
}

#[derive(Debug, Serialize)]
struct Info {
    key: KeyUrlInfo,
    policy: PolicyInfo,
}

#[derive(Debug, Serialize)]
pub struct WkdDiagnostic {
    direct: Info,
    advanced: Info,
}

use http;

fn url_to_req(url: &str) -> http::request::Request<hyper::body::Body> {
    Request::get(url)
        .header(
            "User-Agent",
            "WKDchecker (+https://metacode.biz/openpgp/web-key-directory#2)",
        )
        .body(hyper::body::Body::default())
        .unwrap()
}

use futures::future::{BoxFuture, FutureExt};

fn make_req<'a, T>(
    client: &'a hyper::client::Client<T>,
    url: &'a str,
) -> BoxFuture<'a, hyper::Result<Response<Body>>>
where
    T: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
{
    async move {
        let response = client.request(url_to_req(url)).await;

        if let Ok(ref resp) = response {
            //println!("status: {}", resp.status().as_u16());
            if resp.status().as_u16() == 301 {
                let redirect = resp.headers().get("Location").unwrap().to_str().unwrap();
                //println!("redirect from {} to {}", url, &redirect);
                return make_req(&client, &redirect).await;
            }
        }

        response
    }
    .boxed()
}

#[derive(Debug, Serialize)]
pub struct DiagnosticMessage<'a> {
    pub level: &'static str,
    pub message: Cow<'a, str>,
}

fn key_info_to_messages<'a>(
    prefix: &'static str,
    url: &str,
    email: &str,
    key_info: &'a KeyUrlInfo,
    only_info: bool,
) -> Vec<DiagnosticMessage<'a>> {
    let mut messages = vec![];

    messages.push(DiagnosticMessage {
        level: "info",
        message: format!("{}: key: {}", prefix, url).into(),
    });

    if key_info.status != 200 {
        messages.push(DiagnosticMessage {
            level: if only_info { "info" } else { "error" },
            message: format!("{}: key missing", prefix).into(),
        });
    } else if !key_info.keys.is_empty() {
        for key in &key_info.keys {
            messages.push(DiagnosticMessage {
                level: "success",
                message: format!("{}: found key: {}", prefix, key.fpr).into(),
            });

            let uid = key.get_first_matching_uid(email);

            if let Some(uid) = uid {
                messages.push(DiagnosticMessage {
                    level: "success",
                    message: format!("{}: Key contains correct User ID: {}", prefix, uid).into(),
                });
            } else {
                messages.push(DiagnosticMessage {
                    level: "error",
                    message: format!(
                        "{}: Key does not contain correct User ID: <{}>",
                        prefix, email
                    )
                    .into(),
                });
            }
        }
    } else {
        messages.push(DiagnosticMessage {
            level: "error",
            message: "File exists but it cannot be parsed as an OpenPGP key".into(),
        });
    }

    if let Some(ref cors_value) = key_info.cors {
        if cors_value != "*" {
            messages.push(DiagnosticMessage {
                level: "warning",
                message: format!("{}: CORS header has invalid value: {}", prefix, cors_value)
                    .into(),
            });
        } else {
            messages.push(DiagnosticMessage {
                level: "success",
                message: format!("{}: CORS header is correctly set up", prefix).into(),
            });
        }
    } else {
        messages.push(DiagnosticMessage {
            level: if only_info { "info" } else { "warning" },
            message: format!(
                "{}: `Access-Control-Allow-Origin: *` header is missing",
                prefix
            )
            .into(),
        });
    }

    messages
}

fn policy_info_to_message<'a>(
    prefix: &'static str,
    policy_info: &'a PolicyInfo,
    only_info: bool,
) -> DiagnosticMessage<'a> {
    if policy_info.status / 100 != 2 {
        DiagnosticMessage {
            level: if only_info { "info" } else { "warning" },
            message: format!("{}: Policy file is missing", prefix).into(),
        }
    } else {
        DiagnosticMessage {
            level: "success",
            message: format!("{}: Policy file is present", prefix).into(),
        }
    }
}

pub async fn check_wkd(email: &str) -> Result<WkdDiagnostic, Box<dyn Error>> {
    let client = Client::builder().build::<_, hyper::Body>(HttpsConnector::new());

    let req = Req { email };
    let parts = req.parse();

    let mut urls = join_all(
        vec![
            &parts.direct_key_url,
            &parts.direct_policy_url,
            &parts.advanced_key_url,
            &parts.advanced_policy_url,
        ]
        .iter()
        .map(|url| make_req(&client, url)),
    )
    .await;
    let api = urls.remove(3);
    let a = urls.remove(2);
    let dpi = urls.remove(1);
    let d = urls.remove(0);

    let direct = if d.is_ok() {
        KeyUrlInfo::find_key(parts.direct_key_url, d?).await?
    } else {
        KeyUrlInfo {
            url: parts.direct_key_url,
            cors: None,
            keys: Vec::new(),
            status: 0,
        }
    };

    let direct_policy = PolicyInfo {
        url: parts.direct_policy_url,
        status: dpi.map_or(0, |dpi| dpi.status().as_u16()),
    };

    let advanced = if a.is_ok() {
        KeyUrlInfo::find_key(parts.advanced_key_url, a?).await?
    } else {
        KeyUrlInfo {
            url: parts.advanced_key_url,
            cors: None,
            status: 0,
            keys: Vec::new(),
        }
    };

    let advanced_policy = PolicyInfo {
        url: parts.advanced_policy_url,
        status: api.map_or(0, |api| api.status().as_u16()),
    };

    Ok(WkdDiagnostic {
        direct: Info {
            key: direct,
            policy: direct_policy,
        },
        advanced: Info {
            key: advanced,
            policy: advanced_policy,
        },
    })
}

pub fn lint_wkd<'a>(email: &'a str, diagnostic: &'a WkdDiagnostic) -> Vec<DiagnosticMessage<'a>> {
    let mut messages = vec![];

    for message in key_info_to_messages(
        "Direct",
        &diagnostic.direct.key.url,
        &email,
        &diagnostic.direct.key,
        false,
    ) {
        messages.push(message);
    }
    messages.push(policy_info_to_message(
        "Direct",
        &diagnostic.direct.policy,
        false,
    ));

    for message in key_info_to_messages(
        "Advanced",
        &diagnostic.advanced.key.url,
        &email,
        &diagnostic.advanced.key,
        !diagnostic.direct.key.keys.is_empty(),
    ) {
        messages.push(message);
    }
    messages.push(policy_info_to_message(
        "Advanced",
        &diagnostic.advanced.policy,
        !diagnostic.direct.key.keys.is_empty(),
    ));

    messages
}
