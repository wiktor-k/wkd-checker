use wkd_checker::{check_wkd, lint_wkd, DiagnosticMessage, Req, WkdDiagnostic};

use {
    hyper::{
        service::{make_service_fn, service_fn},
        Body, Request, Response, Server, StatusCode,
    },
    std::net::SocketAddr,
};

use serde::Serialize;

#[derive(Debug, Serialize)]
struct WkdResponse<'a> {
    lint: Vec<DiagnosticMessage<'a>>,
    raw: &'a WkdDiagnostic<'a>,
}

async fn server_req2(req: Request<Body>) -> Result<Response<Body>, Box<dyn std::error::Error>> {
    //let uri = req.uri().to_string();
    //let req = Req { email: uri.split('/').last().unwrap() };
    let bytes = hyper::body::to_bytes(req.into_body()).await?;
    let req: Req = serde_json::from_slice(&bytes)?;
    let parts = req.parse();

    let diagnostic = check_wkd(&parts).await?;

    let lint = lint_wkd(parts.email, &diagnostic);

    Ok(Response::new(Body::from(serde_json::to_string_pretty(
        &WkdResponse {
            lint,
            raw: &diagnostic,
        },
    )?)))
}

async fn serve_req(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    match server_req2(req).await {
        Ok(resp) => Ok(resp),
        Err(ref error) => Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(format!("err: {}", error)))
            .unwrap()),
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Listening on: http://{}", addr);

    // Create a server bound on the provided address
    let serve_future = Server::bind(&addr).serve(make_service_fn(|_| async {
        {
            Ok::<_, hyper::Error>(service_fn(serve_req))
        }
    }));

    if let Err(e) = serve_future.await {
        eprintln!("server error: {}", e);
    }
}
