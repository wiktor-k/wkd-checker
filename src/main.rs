#![feature(backtrace)]

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

async fn server_req2(req: Request<Body>) -> Result<Response<Body>, Box<dyn Error>> {
    // Always return successfully with a response containing a body with
    // a friendly greeting ;)

    println!("Got request at {:?}", req.uri());


    let url: Uri = "https://metacode.biz/sandbox/users.json".parse().unwrap();

    let users: Vec<User> = fetch_json(url).await?;
    //let x = "test";

    println!("users: {:#?}", users);

    let sum = users.iter().fold(0, |acc, user| acc + user.id);
    println!("sum of ids: {}", sum);


    // Return the result of the request directly to the user
    println!("request finished-- returning response");
    Ok(Response::new(Body::from(format!("sum of ids: {}", sum))))
}

#[tokio::main]
async fn main() {
    env_logger::init();

  let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
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

async fn fetch_json(url: hyper::Uri) -> Result<Vec<User>, Box<dyn std::error::Error>> {
    let client = Client::builder().build::<_, hyper::Body>(HttpsConnector::new());

    let res = client.get(url).await?;

    let body = hyper::body::aggregate(res).await?;

    Ok(serde_json::from_reader(body.reader())?)
}
