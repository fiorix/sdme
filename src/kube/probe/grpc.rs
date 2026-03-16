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
        let codec = tonic::codec::ProstCodec::default();
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
