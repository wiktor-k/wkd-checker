use std::borrow::Cow;
use {
    hyper::{
        // Following functions are used by Hyper to handle a `Request`
        // and returning a `Response` in an asynchronous manner by using a Future
        service::{make_service_fn, service_fn},
        // Miscellaneous types from Hyper for working with HTTP.
        Body,
        Client,
        Request,
        Response,
        Server,
        StatusCode,
    },
    std::net::SocketAddr,
};

extern crate sequoia_openpgp as openpgp;
use openpgp::parse::Parse;
use zbase32;

use serde::{Deserialize, Serialize};
use hyper_tls::HttpsConnector;
use std::error::Error;
use log::{warn};
use futures::future::join_all;

#[derive(Debug, Serialize, Deserialize)]
struct MyObj {
    name: String
}

#[derive(Deserialize, Debug)]
struct User {
    id: i32,
    name: String,
}

async fn serve_req(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    match server_req2(req).await {
        Ok(resp) => Ok(resp),
        Err(ref error) => {
            warn!("Unable to locate a razor: {}, retrying", error);
            Ok(
                Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!("err: {}", error)))
                .unwrap()
            )
        }
    }
}

#[derive(Deserialize, Debug)]
struct Req<'a> {
    email: &'a str,
}

#[derive(Debug)]
struct Parts {
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

    fn parse(&self) -> Parts {
        let parts = self.parts();
        let local = parts[0];
        let encoded_local = Self::encoded_part(local.as_bytes());
        let domain = parts[1];
        Parts {
          advanced_key_url: format!("https://openpgpkey.{}/.well-known/openpgpkey/{}/hu/{}?l={}", domain, domain, encoded_local, local),
          advanced_policy_url: format!("https://openpgpkey.{}/.well-known/openpgpkey/{}/policy", domain, domain),
          direct_key_url: format!("https://{}/.well-known/openpgpkey/hu/{}?l={}", domain, encoded_local, local),
          direct_policy_url: format!("https://{}/.well-known/openpgpkey/policy", domain)
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_parsing() {
        let req = crate::Req { email: "eschwartz@archlinux.org" };
        let parts = req.parse();
        assert_eq!(parts.advanced_key_url, "https://openpgpkey.archlinux.org/.well-known/openpgpkey/archlinux.org/hu/ycx3iaqih9tzkfk7dp8jo9xrdepu5m8u?l=eschwartz");
        assert_eq!(parts.advanced_policy_url, "https://openpgpkey.archlinux.org/.well-known/openpgpkey/archlinux.org/policy");
        assert_eq!(parts.direct_key_url, "https://archlinux.org/.well-known/openpgpkey/hu/ycx3iaqih9tzkfk7dp8jo9xrdepu5m8u?l=eschwartz");
        assert_eq!(parts.direct_policy_url, "https://archlinux.org/.well-known/openpgpkey/policy");
    }
}

#[derive(Debug, Serialize)]
struct KeyInfo<'a> {
    url: &'a str,
    cors: Option<String>,
    userids: Vec<String>,
    fpr: Option<String>,
    status: u16,
}

impl<'a> KeyInfo<'a> {
    async fn find_key(url: &'a str, res: Response<Body>) -> Result<KeyInfo<'a>, Box<dyn Error>> {
        let status = res.status();
        if status != 200 {
            return Ok(KeyInfo {
                url,
                cors: None,
                userids: vec![],
                fpr: None,
                status: status.as_u16()
            })
        }

        let cors = res.headers().get("Access-Control-Allow-Origin").map(|h| h.to_str().ok().unwrap_or("").to_owned());

        let bytes = hyper::body::to_bytes(res.into_body()).await?;

        let cert = openpgp::Cert::from_bytes(&bytes.to_vec())?;

        Ok(KeyInfo {
            url,
            cors,
            userids: cert.userids()
                .map(|u| String::from_utf8_lossy(u.value()).into_owned())
                .collect::<Vec<String>>(),
            fpr: Some(cert.fingerprint().to_string()),
            status: status.as_u16()
        })
    }
}

#[derive(Debug, Serialize)]
struct PolicyInfo<'a> {
    url: &'a str,
    status: u16,
}

#[derive(Debug, Serialize)]
struct Info<'a> {
    key: KeyInfo<'a>,
    policy: PolicyInfo<'a>,
}

#[derive(Debug, Serialize)]
struct WkdDiagnostic<'a> {
    direct: Info<'a>,
    advanced: Info<'a>,
}

use http;

fn url_to_req(url: &str) -> http::request::Request<hyper::body::Body> {
  Request::get(url).header("User-Agent", "WKDchecker (+https://metacode.biz/openpgp/web-key-directory#2)")
  .body(hyper::body::Body::default()).unwrap()
}

use futures::future::{BoxFuture, FutureExt};

fn make_req<'a, T>(client: &'a hyper::client::Client::<T>, url: &'a str) ->
BoxFuture<'a, hyper::Result<Response<Body>>>
where T: hyper::client::connect::Connect + Clone + Send + Sync + 'static {
    async move {
        let response = client.request(url_to_req(url)).await;

        if let Ok(ref resp) = response {
            println!("status: {}", resp.status().as_u16());
            if resp.status().as_u16() == 301 {
                let redirect = resp.headers().get("Location").unwrap().to_str().unwrap();
                println!("redirect from {} to {}", url, &redirect);
                return make_req(&client, &redirect).await
            }
        }

        response
    }.boxed()
}

#[derive(Debug, Serialize)]
struct DiagnosticMessage<'a> {
    level: &'static str,
    message: Cow<'a, str>,
}

fn key_info_to_messages<'a>(prefix: &'static str, url: &str, key_info: &'a KeyInfo) -> Vec<DiagnosticMessage<'a>> {
    let mut messages = vec![];

    messages.push(DiagnosticMessage {
        level: "info",
        message: format!("{}: key: {}", prefix, url).into()
    });

    if key_info.status != 200 {
        messages.push(DiagnosticMessage {
            level: "warning",
            message: format!("{}: key missing", prefix).into()
        });
    } else if let Some(ref fpr) = key_info.fpr {
        messages.push(DiagnosticMessage {
            level: "success",
            message: format!("{}: found key: {}", prefix, fpr).into()
        });
    } else {
        messages.push(DiagnosticMessage {
            level: "error",
            message: "File exists but it cannot be parsed as an OpenPGP key".into()
        });
    }

    if let Some(ref cors_value) = key_info.cors {
        if cors_value != "*" {
            messages.push(DiagnosticMessage {
                level: "warning",
                message: format!("{}: CORS header has invalid value: {}", prefix, cors_value).into()
            });
        } else {
            messages.push(DiagnosticMessage {
                level: "success",
                message: format!("{}: CORS header is correctly set up", prefix).into()
            });
        }
    } else {
        messages.push(DiagnosticMessage {
            level: "warning",
            message: format!("{}: CORS header is missing", prefix).into()
        });
    }

    messages
}

fn key_info_uid_to_message<'a>(prefix: &'static str, email: &str, key_info: &'a KeyInfo) -> DiagnosticMessage<'a> {
    let direct_uid = key_info.userids.iter().find(|u| u.contains(&format!("<{}>", email)));

    if let Some(uid) = direct_uid {
        DiagnosticMessage {
            level: "success",
            message: format!("{}: Key contains correct User ID: {}", prefix, uid).into()
        }
    } else {
        DiagnosticMessage {
            level: "error",
            message: format!("{}: Key does not contain correct User ID: <{}>", prefix, email).into()
        }
    }
}

fn policy_info_to_message<'a>(prefix: &'static str, policy_info: &'a PolicyInfo) -> DiagnosticMessage<'a> {
    if policy_info.status / 100 != 2 {
        DiagnosticMessage {
            level: "warning",
            message: format!("{}: Policy file is missing", prefix).into()
        }
    } else {
        DiagnosticMessage {
            level: "success",
            message: format!("{}: Policy file is present", prefix).into()
        }
    }
}

#[derive(Debug, Serialize)]
struct WkdResponse<'a> {
    lint: Vec<DiagnosticMessage<'a>>,
    raw: &'a WkdDiagnostic<'a>,
}

async fn server_req2(req: Request<Body>) -> Result<Response<Body>, Box<dyn Error>> {

    //let uri = req.uri().to_string();
    //let req = Req { email: uri.split('/').last().unwrap() };
    let bytes = hyper::body::to_bytes(req.into_body()).await?;
    let req: Req = serde_json::from_slice(&bytes)?;
    let parts = req.parse();

    println!("for e-mail: {}, {:?}", req.email, parts);

    let client = Client::builder().build::<_, hyper::Body>(HttpsConnector::new());

    let mut urls = join_all(vec![&parts.direct_key_url, &parts.direct_policy_url,
    &parts.advanced_key_url, &parts.advanced_policy_url].iter().map(|url| make_req(&client, url))).await;
    let api = urls.remove(3);
    let a = urls.remove(2);
    let dpi = urls.remove(1);
    let d = urls.remove(0);

    let direct = KeyInfo::find_key(&parts.direct_key_url, d?).await?;

    let direct_policy = PolicyInfo { url: &parts.direct_policy_url, status: dpi?.status().as_u16() };

    let advanced = KeyInfo::find_key(&parts.advanced_key_url, a?).await?;

    let advanced_policy = PolicyInfo { url: &parts.advanced_policy_url, status: api?.status().as_u16() };

    let result = WkdDiagnostic {
        direct: Info {
            key: direct,
            policy: direct_policy,
        },
        advanced: Info {
            key: advanced,
            policy: advanced_policy
        }
    };

    let mut messages = vec![];

    for message in key_info_to_messages("Direct", &parts.direct_key_url, &result.direct.key) {
        messages.push(message);
    }
    messages.push(policy_info_to_message("Direct", &result.direct.policy));
    messages.push(key_info_uid_to_message("Direct", req.email, &result.direct.key));

    for message in key_info_to_messages("Advanced", &parts.advanced_key_url, &result.advanced.key) {
        messages.push(message);
    }
    messages.push(policy_info_to_message("Advanced", &result.advanced.policy));
    messages.push(key_info_uid_to_message("Advanced", req.email, &result.advanced.key));

    Ok(Response::new(Body::from(serde_json::to_string_pretty(&WkdResponse { lint: messages, raw: &result })?)))
}

#[tokio::main]
async fn main() {
    env_logger::init();

  let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
  println!("Listening on http://{}", addr);

  // Create a server bound on the provided address
  let serve_future = Server::bind(&addr)
      .serve(make_service_fn(|_| {
          async {
              {
                  Ok::<_, hyper::Error>(service_fn(serve_req))
              }
          }
      }));

  if let Err(e) = serve_future.await {
      eprintln!("server error: {}", e);
  }
}
