use async_trait::async_trait;
use dashmap::DashMap;
use futures_util::FutureExt;
use log::{error, info};
use once_cell::sync::Lazy;
use pingora::lb::selection::RoundRobin;
use pingora::lb::{discovery, Backend, Backends, LoadBalancer};
use pingora::prelude::TcpHealthCheck;
use pingora::protocols::l4::socket::SocketAddr;
use pingora::proxy::{http_proxy_service, HttpProxy, ProxyHttp, Session};
use pingora::server::configuration::{Opt, ServerConf};
use pingora::services::background::GenBackgroundService;
use pingora::services::listening::Service;
use pingora::upstreams::peer::{HttpPeer, PeerOptions};
use std::collections::BTreeSet;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;
use substring::Substring;

fn new_internal_error(status: u16, message: String) -> pingora::BError {
    pingora::Error::because(
        pingora::ErrorType::HTTPStatus(status),
        message,
        pingora::Error::new(pingora::ErrorType::InternalError),
    )
}

// 全局保存的upstream，用于后续流程中获取
static UPSTREAMS: Lazy<DashMap<String, Arc<Upstream>>> = Lazy::new(|| DashMap::new());

// 添加upstream至全局对象中
fn add_upstream(name: &str, up: Upstream) {
    UPSTREAMS.insert(name.to_string(), Arc::new(up));
}

// 获取对应的upstream
fn get_upstream(name: &str) -> Option<Arc<Upstream>> {
    if let Some(up) = UPSTREAMS.get(&name.to_string()) {
        return Some(up.clone());
    }
    None
}

struct Upstream {
    lb: Arc<LoadBalancer<RoundRobin>>,
    // 是否tls连接
    pub tls: bool,
    // 证书对应的sni
    pub sni: String,
    // 连接节点的相关属性（超时等）
    pub options: PeerOptions,
}

impl Upstream {
    fn new(addrs: Vec<String>) -> pingora::Result<Upstream> {
        let mut upstreams = BTreeSet::new();
        let mut backends = vec![];
        for addr in addrs.iter() {
            // 需要注意，此处如果是域名则会解析为对应的ip
            // 因此如果是域名且ip动态变化的，需要使用另外的服务发现方式
            for item in addr
                .to_socket_addrs()
                .map_err(|e| new_internal_error(500, e.to_string()))?
            {
                backends.push(Backend {
                    addr: SocketAddr::Inet(item),
                    weight: 1,
                });
            }
        }
        upstreams.extend(backends);
        // 静态服务发现，直接使用固定的ip列表，无动态更新
        let discovery = discovery::Static::new(upstreams);
        let backends = Backends::new(discovery);
        // 使用round robin的算法获取upstream节点
        let mut lb = LoadBalancer::<RoundRobin>::from_backends(backends);

        // 使用tcp的方式检测端口，建议使用HttpHealthCheck
        let mut check = TcpHealthCheck::new();
        check.peer_template.options.connection_timeout = Some(Duration::from_secs(3));
        lb.set_health_check(check);

        // 服务发现的刷新间隔，因为是static，所以无需设置
        // lb.update_frequency = Duration::from_secs(60);
        // 健康检测的间隔，根据自己的服务选择合适的值
        lb.health_check_frequency = Some(Duration::from_secs(10));
        // 初始化时首先触发一次更新，生成可使用的upstream节点
        lb.update()
            .now_or_never()
            .expect("static should not block")
            .expect("static should not error");
        Ok(Self {
            lb: Arc::new(lb),
            tls: false,
            sni: "".to_string(),
            options: PeerOptions::new(),
        })
    }
}

struct Loation {
    // 该location对应的前缀
    prefix: String,
    // 该location对应的upstream
    upstream: String,
    // 删除前缀
    replace: bool,
}

struct Server {
    // 监听地址
    addr: String,
    locations: Vec<Loation>,
}
impl Server {
    pub fn new(addr: &str, locations: Vec<Loation>) -> Self {
        Self {
            addr: addr.to_string(),
            locations,
        }
    }
    // 监听对应地址，并返回对应的service
    pub fn run(self, conf: &Arc<ServerConf>) -> Service<HttpProxy<Server>> {
        let addr = self.addr.clone();
        // 创建转发http的服务
        let mut lb = http_proxy_service(conf, self);
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
    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut (),
    ) -> pingora::Result<Box<HttpPeer>> {
        let header = session.req_header_mut();
        let path = header.uri.path().to_string();

        let location = self
            .locations
            .iter()
            .find(|item| path.starts_with(item.prefix.as_str()))
            .ok_or(new_internal_error(
                500,
                "无法获取匹配的location".to_string(),
            ))?;
        if location.replace {
            let mut uri = path
                .substring(location.prefix.len(), path.len())
                .to_string();
            if let Some(query) = header.uri.query() {
                uri = format!("{path}?{query}");
            }
            if let Err(e) = uri.parse::<http::Uri>().map(|uri| header.set_uri(uri)) {
                error!("error: {}", e.to_string());
            }
        }

        // 获取对应的upstream
        let up = get_upstream(&location.upstream).ok_or(new_internal_error(
            500,
            "无法获取对应的upstream".to_string(),
        ))?;
        // 根据upstream的load balancer获取对应的节点
        let backend = up
            .lb
            .select(b"", 256)
            .ok_or(new_internal_error(500, "无法获取对应的backend".to_string()))?;
        info!("path: {path}, upstream peer is: {:?}", backend);

        let mut peer = Box::new(HttpPeer::new(backend.addr, up.tls, up.sni.clone()));
        peer.options = up.options.clone();

        Ok(peer)
    }
}

// 需要注意，此为演示代码因此有部分代码直接使用unwrap，正式使用时建议针对错误按正常处理
// RUST_LOG=INFO cargo run --example 前缀匹配location
fn main() {
    env_logger::init();
    // 初始化pingora实例
    let mut instance = pingora::server::Server::new(Some(Opt {
        ..Default::default()
    }))
    .unwrap();
    // 实例启动前的相关初始化
    instance.bootstrap();

    let charts_upstream = "charts";
    let charts = Upstream::new(vec![
        "127.0.0.1:5000".to_string(),
        "127.0.0.1:5001".to_string(),
    ])
    .unwrap();
    // 添加对应的health check后台服务
    instance.add_service(GenBackgroundService::new(
        "charts health check".to_string(),
        charts.lb.clone(),
    ));
    add_upstream(charts_upstream, charts);

    let diving_upstream = "diving";
    let diving = Upstream::new(vec!["127.0.0.1:6005".to_string()]).unwrap();
    instance.add_service(GenBackgroundService::new(
        "diving healt check".to_string(),
        diving.lb.clone(),
    ));
    add_upstream(diving_upstream, diving);

    // 初始化服务，监听地址为：127.0.0.1:6118
    let server = Server::new(
        "127.0.0.1:6118",
        vec![
            Loation {
                prefix: "/diving".to_string(),
                upstream: diving_upstream.to_string(),
                replace: true,
            },
            Loation {
                prefix: "/".to_string(),
                upstream: charts_upstream.to_string(),
                replace: false,
            },
        ],
    );
    // 添加http服务至当前实例中
    instance.add_service(server.run(&instance.configuration));
    instance.run_forever();
}
