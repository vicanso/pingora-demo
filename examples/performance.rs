use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use log::info;
use pingora::http::ResponseHeader;
use pingora::proxy::{http_proxy_service, HttpProxy, ProxyHttp, Session};
use pingora::server::configuration::{Opt, ServerConf};
use pingora::services::listening::Service;
use pingora::upstreams::peer::HttpPeer;
use std::env;
use std::sync::Arc;

struct Server {
    // 监听地址
    addr: String,
    threads: usize,
}
impl Server {
    pub fn new(addr: &str, threads: usize) -> Self {
        Self {
            threads,
            addr: addr.to_string(),
        }
    }
    // 监听对应地址，并返回对应的service
    pub fn run(self, conf: &Arc<ServerConf>) -> Service<HttpProxy<Server>> {
        let threads = Some(self.threads);
        let addr = self.addr.clone();
        // 创建转发http的服务
        let mut lb = http_proxy_service(conf, self);
        lb.threads = threads;
        // 添加tcp监听地址
        lb.add_tcp(&addr);
        // 返回pingora service，用于添加至实例中
        lb
    }
}

/// Http转发的trait需要实现两个方法，`new_ctx`与`upstream_peer`
#[async_trait]
impl ProxyHttp for Server {
    type CTX = ();
    // 用于记录处理流程中的数据，暂时未使用
    fn new_ctx(&self) -> Self::CTX {}
    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        let mut header = ResponseHeader::build(StatusCode::OK, Some(3))?;
        let body = Bytes::from("pong");
        header.insert_header(http::header::CONTENT_LENGTH, body.len().to_string())?;
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session.write_response_body(Some(body), true).await?;
        session.finish_body().await?;
        Ok(true)
    }
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut (),
    ) -> pingora::Result<Box<HttpPeer>> {
        return Err(pingora::Error::because(
            pingora::ErrorType::HTTPStatus(500),
            "No Upstream",
            pingora::Error::new(pingora::ErrorType::InternalError),
        ));
    }
}

// 需要注意，此为演示代码因此有部分代码直接使用unwrap，正式使用时建议针对错误按正常处理
// RUST_LOG=INFO cargo run --example 初窥门径
fn main() {
    env_logger::init();
    // 初始化pingora实例
    let mut instance = pingora::server::Server::new(Some(Opt {
        ..Default::default()
    }))
    .unwrap();
    let mut threads = 1;
    for arg in env::args().skip(1) {
        let value = arg.parse::<usize>().unwrap_or_default();
        if value > 0 {
            threads = value;
        }
    }
    info!("threads: {threads}");
    // 实例启动前的相关初始化
    instance.bootstrap();

    // 初始化服务，监听地址为：127.0.0.1:6118
    let server = Server::new("127.0.0.1:6118", threads);
    // 添加http服务至当前实例中
    instance.add_service(server.run(&instance.configuration));
    instance.run_forever();
}
