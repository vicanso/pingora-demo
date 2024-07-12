use async_trait::async_trait;
use dashmap::DashMap;
use futures_util::FutureExt;
use log::{error, info};
use once_cell::sync::Lazy;
use pingora::http::RequestHeader;
use pingora::lb::selection::RoundRobin;
use pingora::lb::{discovery, Backend, Backends, LoadBalancer};
use pingora::listeners::TlsSettings;
use pingora::prelude::TcpHealthCheck;
use pingora::protocols::l4::socket::SocketAddr;
use pingora::proxy::{http_proxy_service, HttpProxy, ProxyHttp, Session};
use pingora::server::configuration::{Opt, ServerConf};
use pingora::services::background::GenBackgroundService;
use pingora::services::listening::Service;
use pingora::tls::ext;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::{NameType, SslRef};
use pingora::tls::x509::X509;
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

// https证书相关数据
type Certificate = (X509, PKey<Private>);
pub fn parse_certificate(cert: &[u8], key: &[u8]) -> Certificate {
    let cert = X509::from_pem(cert).unwrap();
    let key = PKey::private_key_from_pem(key).unwrap();
    (cert, key)
}
// 全局保存https证书
static CERTS: Lazy<DashMap<String, Certificate>> = Lazy::new(|| DashMap::new());
// 添加https证书
fn add_certificate(domain: &str, cert: &[u8], key: &[u8]) {
    CERTS.insert(domain.to_string(), parse_certificate(cert, key));
}
pub struct DynamicCertificate {}

#[async_trait]
impl pingora::listeners::TlsAccept for DynamicCertificate {
    // tls握手时的回访函数
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        // 获取对应的服务名称
        let server_name = ssl.servername(NameType::HOST_NAME).unwrap();
        // 获取对应ygnh
        let result = CERTS.get(server_name).unwrap();
        // 设置认证使用的相关信息
        let _ = ext::ssl_use_certificate(ssl, &result.0);
        let _ = ext::ssl_use_private_key(ssl, &result.1);
    }
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

impl Loation {
    pub fn matched(&self, path: &str) -> bool {
        // 判断是否包括该前缀
        path.starts_with(&self.prefix)
    }
    pub fn rewrite(&self, header: &mut RequestHeader) -> Option<String> {
        // 无需重写
        if !self.replace {
            return None;
        }
        // 重写url，删除前缀
        let path = header.uri.path();
        let mut uri = path.substring(self.prefix.len(), path.len()).to_string();
        if let Some(query) = header.uri.query() {
            uri = format!("{path}?{query}");
        }
        Some(uri)
    }
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
        let tls_settings = TlsSettings::with_callbacks(Box::new(DynamicCertificate {})).unwrap();
        // 添加tls监听地址以及证书处理逻辑
        lb.add_tls_with_settings(&addr, None, tls_settings);
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
            .find(|item| item.matched(&path))
            .ok_or(new_internal_error(
                500,
                "无法获取匹配的location".to_string(),
            ))?;
        if let Some(uri) = location.rewrite(header) {
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

fn get_tls_pem() -> (String, String) {
    (
        r###"-----BEGIN CERTIFICATE-----
MIID/TCCAmWgAwIBAgIQJUGCkB1VAYha6fGExkx0KTANBgkqhkiG9w0BAQsFADBV
MR4wHAYDVQQKExVta2NlcnQgZGV2ZWxvcG1lbnQgQ0ExFTATBgNVBAsMDHZpY2Fu
c29AdHJlZTEcMBoGA1UEAwwTbWtjZXJ0IHZpY2Fuc29AdHJlZTAeFw0yNDA3MDYw
MjIzMzZaFw0yNjEwMDYwMjIzMzZaMEAxJzAlBgNVBAoTHm1rY2VydCBkZXZlbG9w
bWVudCBjZXJ0aWZpY2F0ZTEVMBMGA1UECwwMdmljYW5zb0B0cmVlMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv5dbylSPQNARrpT/Rn7qZf6JmH3cueMp
YdOpctuPYeefT0Jdgp67bg17fU5pfyR2BWYdwyvHCNmKqLdYPx/J69hwTiVFMOcw
lVQJjbzSy8r5r2cSBMMsRaAZopRDnPy7Ls7Ji+AIT4vshUgL55eR7ACuIJpdtUYm
TzMx9PTA0BUDkit6z7bTMaEbjDmciIBDfepV4goHmvyBJoYMIjnAwnTFRGRs/QJN
d2ikFq999fRINzTDbRDP1K0Kk6+zYoFAiCMs9lEDymu3RmiWXBXpINR/Sv8CXtz2
9RTVwTkjyiMOPY99qBfaZTiy+VCjcwTGKPyus1axRMff4xjgOBewOwIDAQABo14w
XDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHwYDVR0jBBgw
FoAUhU5Igu3uLUabIqUhUpVXjk1JVtkwFAYDVR0RBA0wC4IJcGluZ2FwLmlvMA0G
CSqGSIb3DQEBCwUAA4IBgQDBimRKrqnEG65imKriM2QRCEfdB6F/eP9HYvPswuAP
tvQ6m19/74qbtkd6vjnf6RhMbj9XbCcAJIhRdnXmS0vsBrLDsm2q98zpg6D04F2E
L++xTiKU6F5KtejXcTHHe23ZpmD2XilwcVDeGFu5BEiFoRH9dmqefGZn3NIwnIeD
Yi31/cL7BoBjdWku5Qm2nCSWqy12ywbZtQCbgbzb8Me5XZajeGWKb8r6D0Nb+9I9
OG7dha1L3kxerI5VzVKSiAdGU0C+WcuxfsKAP8ajb1TLOlBaVyilfqmiF457yo/2
PmTYzMc80+cQWf7loJPskyWvQyfmAnSUX0DI56avXH8LlQ57QebllOtKgMiCo7cr
CCB2C+8hgRNG9ZmW1KU8rxkzoddHmSB8d6+vFqOajxGdyOV+aX00k3w6FgtHOoKD
Ztdj1N0eTfn02pibVcXXfwESPUzcjERaMAGg1hoH1F4Gxg0mqmbySAuVRqNLnXp5
CRVQZGgOQL6WDg3tUUDXYOs=
-----END CERTIFICATE-----"###
            .to_string(),
        r###"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC/l1vKVI9A0BGu
lP9Gfupl/omYfdy54ylh06ly249h559PQl2CnrtuDXt9Tml/JHYFZh3DK8cI2Yqo
t1g/H8nr2HBOJUUw5zCVVAmNvNLLyvmvZxIEwyxFoBmilEOc/LsuzsmL4AhPi+yF
SAvnl5HsAK4gml21RiZPMzH09MDQFQOSK3rPttMxoRuMOZyIgEN96lXiCgea/IEm
hgwiOcDCdMVEZGz9Ak13aKQWr3319Eg3NMNtEM/UrQqTr7NigUCIIyz2UQPKa7dG
aJZcFekg1H9K/wJe3Pb1FNXBOSPKIw49j32oF9plOLL5UKNzBMYo/K6zVrFEx9/j
GOA4F7A7AgMBAAECggEAWNDkx2XtxsDuAX2m3VpGdSPLS3rFURMCgwwpGEq6LEvA
qXB9gujswHbVkWBBPaR8ZcJR98EaknquccoUyaaF56Q9Y6yZZ7M07XS4vREUs06T
8wEX9Ec6BcjTOW/77BGpAGjyO7qOf7nA2oRsqF62Ua57CjglSryLU9nKxeCUZaEa
HWbpn/AVieddIBdCSK1ANFgXb1ySA3Rh2IaMggql1n2+gk2s4qyAScarNSz0PDps
v65iK1ZAABmQEItsklBE8XddIK0BE5ciaLShK+BLX/bnPjCle2QGdDOtbNKfn3Ab
8gMmY9q4/isO0i8njeNWtgrmOKpL8ETxbzCDGwqdEQKBgQDxe3nuxeDJSXUaj4Vl
LMJ+jln8AZTEegt5T0lm3kke4vJTyQAjwCtWrxB8xario5uWwf0Np/NvLvqJI7e4
+KIJF/5Vy15QngUHJ0c5D8Fm0DufWI9btuZDG3EYeqs4NRbc1Vu+QBziwZXvemkU
2hHwnVYn3lc2WKgiEXcLf2SAQwKBgQDLHAkc9JzWOnj6YIb/WWLGQxu7kVW6T3Fr
f+c4IZN9IhbjxrRilMG0Z/kQDX8dD2b3suOD+QjBZ1rJR34xDVGPPhbHx+3j+2rK
piUZLPAqk+vODHlx9ST9V7RklZnsitQpxZLI5OhylIKXkTk6I92jDUJNRF9ooeoV
zi2FHQasqQKBgFJg0g7PeEiSg51k+peyNkNgInhivbJtA/8FOkAaco1T1GEav65y
fxZaMGCwOgSI1aoPUVlYQyZZu2QPSDyUrQo3Ii94ahtMXOC82IIxysNdJAnO91DN
Sy33bZRxPHm3Oq5pJpv3WSNN8O06MCDJ57bSpbKCGfRTOEAu/xJwCgPrAoGBALtv
GN3WwvFTrpboA0yb8XIjNfGHMkSn0XQx6W+8VH5SuirjEU40FvnkRUzSF676qrwF
Ir6ET9cjCP3ccxDTSKPW2XDuCJOuTaPLZUrxVIUGUsKocl5+qu78Q+XaxNwsVZRi
1o176SLr+APlKZmExaEVuEzTvvQxD3Ol/A3udl1ZAoGBAKztzGZc2YG5nw62kJ8J
1XBrQG1rWuAMgrVbo/aDnPs04E31tPEOrZ2m7pKr/uGmf74OQeQrUaQ0+A5YZxrD
vmkKQHwfyX6cFGxuXwyCZa7q1E83qFNLPSZ0ZF8DHiJqeunLchxYm4uA4Y8BO1jK
aqcrKJfS+xaKWxXPiNlpBMG5
-----END PRIVATE KEY-----"###
            .to_string(),
    )
}

// 需要注意，此为演示代码因此有部分代码直接使用unwrap，正式使用时建议针对错误按正常处理
// RUST_LOG=INFO cargo run --example 多域名https
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

    // 添加localhost方便开发测试
    for domain in ["pingap.io", "github.com", "localhost"] {
        let (cert, key) = get_tls_pem();
        add_certificate(domain, cert.as_bytes(), key.as_bytes());
    }

    // 初始化服务，监听地址为：127.0.0.1:6118
    let server = Server::new(
        "127.0.0.1:6118",
        // 需要注意要按权重添加
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
