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
        Uri,
        StatusCode,
    },
    std::net::SocketAddr,
};

extern crate sequoia_openpgp as openpgp;
use openpgp::parse::Parse;
use zbase32;

use serde::{Deserialize, Serialize};
use hyper_tls::HttpsConnector;
use bytes::buf::BufExt as _;
use std::error::Error;
use log::{info, trace, warn};


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
struct KeyInfo {
    url: String,
    fpr: Option<String>,
    status: u16,
}

impl KeyInfo {
    async fn find_key(url: String, res: Response<Body>) -> Result<KeyInfo, Box<dyn Error>> {
        let status = res.status();
        if status != 200 {
            return Ok(KeyInfo {
                url,
                fpr: None,
                status: status.as_u16()
            })
        }
        let bytes = hyper::body::to_bytes(res.into_body()).await?;

        let cert = openpgp::Cert::from_bytes(&bytes.to_vec())?;
        println!("fp: {}", cert.fingerprint());

        Ok(KeyInfo {
            url,
            fpr: Some(cert.fingerprint().to_string()),
            status: status.as_u16()
        })
    }
}

#[derive(Debug, Serialize)]
struct PolicyInfo {
    url: String,
    status: u16,
}

#[derive(Debug, Serialize)]
struct Info {
    key: KeyInfo,
    policy: PolicyInfo,
}

#[derive(Debug, Serialize)]
struct WkdDiagnostic {
    direct: Info,
    advanced: Info,
}

async fn server_req2(req: Request<Body>) -> Result<Response<Body>, Box<dyn Error>> {

    /*
    let bytes = hyper::body::to_bytes(req.into_body()).await?;
    let req: Req = serde_json::from_slice(&bytes)?;
    */
    let uri = req.uri().to_string();
    let req = Req { email: uri.split('/').last().unwrap() };
    let parts = req.parse();

    println!("for e-mail: {}, {:?}", req.email, parts);

    let client = Client::builder().build::<_, hyper::Body>(HttpsConnector::new());

    let url = parts.direct_key_url.parse().unwrap();
    let res = client.get(url).await?;
    let direct = KeyInfo::find_key(parts.direct_key_url, res).await?;

    let url = parts.direct_policy_url.parse().unwrap();
    let res = client.get(url).await?;
    let direct_policy = PolicyInfo { url: parts.direct_policy_url, status: res.status().as_u16() };

    let url = parts.advanced_key_url.parse().unwrap();
    let res = client.get(url).await?;
    let advanced = KeyInfo::find_key(parts.advanced_key_url, res).await?;

    let url = parts.advanced_policy_url.parse().unwrap();
    let res = client.get(url).await?;
    let advanced_policy = PolicyInfo { url: parts.advanced_policy_url, status: res.status().as_u16() };

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

    /*for uid in cert.userids() {
        s = format!("{}{}", s, *uid);
    }*/

    Ok(Response::new(Body::from(serde_json::to_string_pretty(&result)?)))
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
