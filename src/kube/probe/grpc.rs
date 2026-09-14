//! gRPC health check probe using tonic.
//!
//! Implements the gRPC Health Checking Protocol (grpc.health.v1.Health/Check)
//! with manually defined protobuf types to avoid a tonic-health dependency.

use std::time::Duration;

/// Protobuf types for gRPC Health Checking Protocol.
mod pb {
    #[derive(Clone, prost::Message)]
    pub struct HealthCheckRequest {
        #[prost(string, tag = "1")]
        pub service: String,
    }

    #[derive(Clone, prost::Message)]
    pub struct HealthCheckResponse {
        #[prost(enumeration = "ServingStatus", tag = "1")]
        pub status: i32,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
    #[repr(i32)]
    pub enum ServingStatus {
        Unknown = 0,
        Serving = 1,
        NotServing = 2,
        ServiceUnknown = 3,
    }
}

/// gRPC health check client.
struct HealthClient {
    inner: tonic::client::Grpc<tonic::transport::Channel>,
}

impl HealthClient {
    fn new(channel: tonic::transport::Channel) -> Self {
        Self {
            inner: tonic::client::Grpc::new(channel),
        }
    }

    async fn check(
        &mut self,
        request: pb::HealthCheckRequest,
    ) -> Result<tonic::Response<pb::HealthCheckResponse>, tonic::Status> {
        self.inner
            .ready()
            .await
            .map_err(|e| tonic::Status::unknown(format!("service not ready: {e}")))?;
        let codec = tonic_prost::ProstCodec::default();
        let path = "/grpc.health.v1.Health/Check".parse().expect("valid path");
        self.inner
            .unary(tonic::Request::new(request), path, codec)
            .await
    }
}

/// Check gRPC health of a service.
pub fn check(port: u16, service: Option<&str>, timeout_secs: u32) -> bool {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return false,
    };

    rt.block_on(async {
        let timeout = Duration::from_secs(timeout_secs as u64);
        let endpoint = format!("http://127.0.0.1:{port}");

        let channel = match tonic::transport::Endpoint::from_shared(endpoint) {
            Ok(ep) => match ep.connect_timeout(timeout).timeout(timeout).connect().await {
                Ok(c) => c,
                Err(_) => return false,
            },
            Err(_) => return false,
        };

        let mut client = HealthClient::new(channel);
        let request = pb::HealthCheckRequest {
            service: service.unwrap_or("").to_string(),
        };

        match client.check(request).await {
            Ok(resp) => resp.into_inner().status == pb::ServingStatus::Serving as i32,
            Err(_) => false,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use std::convert::Infallible;
    use std::task::{Context, Poll};
    use tonic::codegen::{http, BoxFuture, Service};

    #[test]
    fn health_messages_match_protocol_wire_format() {
        let request = pb::HealthCheckRequest {
            service: "db".into(),
        };
        assert_eq!(request.encode_to_vec(), b"\x0a\x02db");
        let response = pb::HealthCheckResponse::decode(&b"\x08\x01"[..]).unwrap();
        assert_eq!(response.status, pb::ServingStatus::Serving as i32);
        assert!(pb::HealthCheckResponse::decode(&b"\x08\x80"[..]).is_err());
    }

    #[derive(Clone)]
    struct HealthService;

    impl tonic::server::NamedService for HealthService {
        const NAME: &'static str = "grpc.health.v1.Health";
    }

    impl tonic::server::UnaryService<pb::HealthCheckRequest> for HealthService {
        type Response = pb::HealthCheckResponse;
        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

        fn call(&mut self, request: tonic::Request<pb::HealthCheckRequest>) -> Self::Future {
            Box::pin(async move {
                let status = match request.into_inner().service.as_str() {
                    "" | "db" => pb::ServingStatus::Serving as i32,
                    "stopped" => pb::ServingStatus::NotServing as i32,
                    "unknown" => pb::ServingStatus::Unknown as i32,
                    "missing" => pb::ServingStatus::ServiceUnknown as i32,
                    "future-status" => 99,
                    "slow" => {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        pb::ServingStatus::Serving as i32
                    }
                    _ => return Err(tonic::Status::unavailable("health unavailable")),
                };
                Ok(tonic::Response::new(pb::HealthCheckResponse { status }))
            })
        }
    }

    impl Service<http::Request<tonic::body::Body>> for HealthService {
        type Response = http::Response<tonic::body::Body>;
        type Error = Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
            assert_eq!(request.uri().path(), "/grpc.health.v1.Health/Check");
            Box::pin(async move {
                let codec = tonic_prost::ProstCodec::default();
                Ok(tonic::server::Grpc::new(codec)
                    .unary(HealthService, request)
                    .await)
            })
        }
    }

    #[test]
    fn health_probe_checks_loopback_responses_and_deadlines() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let incoming =
                tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse().unwrap())
                    .unwrap();
            let port = incoming.local_addr().unwrap().port();
            let server = tokio::spawn(
                tonic::transport::Server::builder()
                    .add_service(HealthService)
                    .serve_with_incoming(incoming),
            );
            for (service, expected) in [
                (None, true),
                (Some("db"), true),
                (Some("stopped"), false),
                (Some("unknown"), false),
                (Some("missing"), false),
                (Some("future-status"), false),
                (Some("error"), false),
                (Some("slow"), false),
            ] {
                let result = tokio::task::spawn_blocking(move || check(port, service, 1))
                    .await
                    .unwrap();
                assert_eq!(result, expected, "service: {service:?}");
            }
            server.abort();
            assert!(server.await.unwrap_err().is_cancelled());
        });
    }
}
