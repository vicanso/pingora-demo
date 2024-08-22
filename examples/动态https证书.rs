use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use futures_util::FutureExt;
use http::StatusCode;
use log::{error, info};
use once_cell::sync::Lazy;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::lb::selection::RoundRobin;
use pingora::lb::{discovery, Backend, Backends, LoadBalancer};
use pingora::listeners::TlsSettings;
use pingora::prelude::{background_service, TcpHealthCheck};
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
pub(crate) fn add_certificate(domain: &str, cert: &[u8], key: &[u8]) {
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
    pub fn run(self, conf: &Arc<ServerConf>, tls: bool) -> Service<HttpProxy<Server>> {
        let addr = self.addr.clone();
        // 创建转发http的服务
        let mut lb = http_proxy_service(conf, self);
        if tls {
            let tls_settings =
                TlsSettings::with_callbacks(Box::new(DynamicCertificate {})).unwrap();
            // 添加tls监听地址以及证书处理逻辑
            lb.add_tls_with_settings(&addr, None, tls_settings);
        } else {
            lb.add_tcp(&addr);
        }
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
        // 如果有对应的认证token，则返回对应数据
        // 用于let's encrypt 的http challenge验证
        if let Some(token) = lets_encrypt::get_auth_token(session.req_header().uri.path()) {
            let mut header = ResponseHeader::build(StatusCode::OK, Some(3))?;
            let body = Bytes::from(token);
            header.insert_header(http::header::CONTENT_LENGTH, body.len().to_string())?;
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session.write_response_body(Some(body), true).await?;
            session.finish_body().await?;
            return Ok(true);
        }
        Ok(false)
    }
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

mod lets_encrypt {
    use super::add_certificate;
    use async_trait::async_trait;
    use dashmap::DashMap;
    use instant_acme::{
        Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus,
    };
    use log::info;
    use once_cell::sync::Lazy;
    use pingora::server::ShutdownWatch;
    use pingora::services::background::BackgroundService;
    use std::time::Duration;
    use tokio::time::interval;

    static AUTH_TOKENS: Lazy<DashMap<String, String>> = Lazy::new(|| DashMap::new());

    static PATH_PREFIX: &str = "/.well-known/acme-challenge/";

    pub fn get_auth_token(path: &str) -> Option<String> {
        if let Some(value) = AUTH_TOKENS.get(path) {
            Some(value.clone())
        } else {
            None
        }
    }

    pub struct LetsEncryptService {
        domains: Vec<String>,
    }

    pub fn new_lets_encrypt_service(domains: Vec<String>) -> LetsEncryptService {
        LetsEncryptService { domains }
    }

    #[async_trait]
    impl BackgroundService for LetsEncryptService {
        async fn start(&self, mut shutdown: ShutdownWatch) {
            new_lets_encrypt(&self.domains).await;
            let mut period = interval(Duration::from_secs(30 * 24 * 3600));
            loop {
                tokio::select! {
                    _ = shutdown.changed() => {
                        break;
                    }
                    _ = period.tick() => {
                       new_lets_encrypt(&self.domains).await;
                    }
                }
            }
        }
    }

    async fn new_lets_encrypt(domains: &[String]) {
        //
        let (account, _) = Account::create(
            &NewAccount {
                // 联系人列表，可填空
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            // 正式使用时替换为 LetsEncrypt::Production.url()
            LetsEncrypt::Staging.url(),
            None,
        )
        .await
        .unwrap();

        // 创建申请证书订单，需要注意域名ip需要解析为当前服务运行的ip
        // 用于后续let's encrypt验证服务对域名的所有权
        let mut order = account
            .new_order(&NewOrder {
                identifiers: &domains
                    .iter()
                    .map(|item| Identifier::Dns(item.to_owned()))
                    .collect::<Vec<Identifier>>(),
            })
            .await
            .unwrap();
        let state = order.state();
        if !matches!(state.status, OrderStatus::Pending) {
            // 申请订单状态不对，直接退出（需要注意，正式使用时通过error返回，而非直接退出）
            panic!("order status is not pending");
        }

        // 获取后续认证信息
        let authorizations = order.authorizations().await.unwrap();
        let mut challenges = Vec::with_capacity(authorizations.len());

        // 根据认证信息生成http challenge
        for authz in &authorizations {
            match authz.status {
                instant_acme::AuthorizationStatus::Pending => {}
                instant_acme::AuthorizationStatus::Valid => continue,
                _ => todo!(),
            }

            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Http01)
                .unwrap();

            let instant_acme::Identifier::Dns(identifier) = &authz.identifier;

            let key_auth = order.key_authorization(challenge);
            info!("let's encrypt token: {}", challenge.token);

            // 记录token与auth的对照关系，用于后续的http challenge
            // http://your-domain/.well-known/acme-challenge/<TOKEN>
            let path = format!("{PATH_PREFIX}{}", challenge.token);
            AUTH_TOKENS.insert(path, key_auth.as_str().to_string());
            challenges.push((identifier, &challenge.url));
        }

        // 设置为http challenge 为已准备好状态
        for (_, url) in &challenges {
            order.set_challenge_ready(url).await.unwrap();
        }

        let mut tries = 1u8;
        let mut delay = Duration::from_millis(250);
        let detail_url = authorizations.first();
        // 一直检测订单状态，判断是否已完成http challenge
        let state = loop {
            let state = order.state();
            if let OrderStatus::Ready | OrderStatus::Invalid | OrderStatus::Valid = state.status {
                break state;
            }
            order.refresh().await.unwrap();

            // 等待时长*2
            delay *= 2;
            tries += 1;
            // 最多只检测10次
            match tries < 10 {
                true => info!("Order is not ready, waiting {delay:?}"),
                false => {
                    let error = format!(
                        "Giving up: order is not ready. For details, see the url: {detail_url:?}"
                    );
                    panic!("{}", error);
                }
            }
            tokio::time::sleep(delay).await;
        };

        if state.status == OrderStatus::Invalid {
            panic!("{}", format!("order is invalid, check {detail_url:?}"));
        }

        // 生成https证书
        let mut names = Vec::with_capacity(challenges.len());
        for (identifier, _) in challenges {
            names.push(identifier.to_owned());
        }
        let mut params = rcgen::CertificateParams::new(names.clone()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        // 生成private key
        let private_key = rcgen::KeyPair::generate().unwrap();
        let csr = params.serialize_request(&private_key).unwrap();
        order.finalize(csr.der()).await.unwrap();
        let cert_chain_pem = loop {
            match order.certificate().await.unwrap() {
                Some(cert_chain_pem) => break cert_chain_pem,
                None => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        };
        // 将域名与对其对应证书添加至全局证书实例中
        // 实际使用时，由于let's encrypt有限制申请证书的次数
        // 因此需要将申请到的证书保存，用于后续使用
        for domain in domains {
            add_certificate(
                domain,
                cert_chain_pem.as_bytes(),
                private_key.serialize_pem().as_bytes(),
            )
        }
    }
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

    // 初始化服务，监听地址为：127.0.0.1:6118
    let tls_server = Server::new(
        "127.0.0.1:443",
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
    // 80端口提供http服务，用于let's encrypt 的http challenge
    let http_server = Server::new(
        "127.0.0.1:80",
        // 需要注意要按权重添加
        vec![],
    );
    // 后台服务运行申请证书逻辑
    instance.add_service(background_service(
        "letsEncrypt",
        lets_encrypt::new_lets_encrypt_service(vec!["pingap.io".to_string()]),
    ));
    // 添加http服务至当前实例中
    instance.add_service(tls_server.run(&instance.configuration, true));
    instance.add_service(http_server.run(&instance.configuration, false));
    instance.run_forever();
}
