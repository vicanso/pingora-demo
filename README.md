# pingora-demo

介绍如何使用pingora开发反向代理，记录了我开始[pingap](https://github.com/vicanso/pingap)时了解到的相关技术与处理流程。

### 自定义出错响应

pingora的`respond_error`函数在响应出错时，因为未针对错误类型判断，所有的出错响应均设置了`self.set_keepalive(None)`，因此在编写自定义的错误处理，可直接设置响应数据，而非返回`Err(error)`的形式。

如下面的例子是在`request_filter`的认证失败，直接返回`401`:

```rust
async fn request_filter(
    &self,
    session: &mut Session,
    _ctx: &mut Self::CTX,
) -> pingora::Result<bool>
where
    Self::CTX: Send + Sync,
{
    if session.req_header().uri.path() != "/login" {
        // 生成http响应头
        let mut header = ResponseHeader::build_no_case(401, None).unwrap();
        // 响应数据
        let body = bytes::Bytes::from_static(b"Unauthorized");
        // 设置数据长度
        header.insert_header("Content-Length", body.len().to_string())?;
        // 返回响应数据
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session.write_response_body(Some(body), true).await?;
        session.finish_body().await?;
        // 设置为已完成http请求，不再执行后续流程
        return Ok(true);
    }
    Ok(false)
}
```

### tcp、tls连接耗时记录

`ProxyHttp`的相关逻辑已经是在http协议层，若需要获取tcp和tls的相关连接数据可从`session.digest`中获取，在`ProxyHttp`中的步骤均可获取，代码如下：

```rust
async fn upstream_peer(
    &self,
    session: &mut Session,
    _ctx: &mut (),
) -> pingora::Result<Box<HttpPeer>> {
    println!("{:?}", session.digest());

    let value: u8 = rand::random();
    // 随机选择对应的upstream节点
    let addr = if value % 2 == 0 {
        "127.0.0.1:5000"
    } else {
        "127.0.0.1:5001"
    };
    let peer = Box::new(HttpPeer::new(addr, false, "".to_string()));
    Ok(peer)
}
```

```bash
Some(Digest { ssl_digest: None, timing_digest: [Some(TimingDigest { established_ts: SystemTime { tv_sec: 1720844142, tv_nsec: 251386000 } })], proxy_digest: None, socket_digest: Some(SocketDigest { raw_fd: 14, peer_addr: OnceCell(Some(Inet(127.0.0.1:64530))), local_addr: OnceCell(Uninit) }) })
```
digest中有ssl的相关信息，timing主要是tcp与tls的信息，以及socket的信息均可获取。

### H2C

pingora在0.3.0版本开始支持h2c协议，主要用于内部服务间希望使用http2(grpc)，但又非https的相关应用，代码也比较简单，在初始化好http proxy service之后，设置server options即可，代码如下：

```rust
let mut lb = http_proxy_service(conf, self);
if let Some(http_logic) = lb.app_logic_mut() {
    let mut http_server_options = HttpServerOptions::default();
    http_server_options.h2c = true;
    http_logic.server_options = Some(http_server_options);
}
```

### TLS1.1

pingora使用的openssl，默认是不支持tls1.1的（也不建议使用），但是因为一些无法解决的原因，需要支持tls1.1，则在初始化tls的配置之后，还需设置以下配置：


```rust
tls_settings.set_security_level(0);
tls_settings
    .clear_options(pingora::tls::ssl::SslOptions::NO_TLSV1_1);
// 按应用场景设置相应的加解密方法
```

### 数据压缩服务

pingora支持了多种压缩算法，常用的是：`zstd`, `brotli`以及`gzip`三种压缩算法，简单的设置对应压缩级别即可用，但是由于浏览器的Accept-Encoding是`gzip, deflate, br, zstd`，所以若希望优先使用`zstd`则需要修改请求头的`Accept-Encoding`。下面是设置支持相应的压缩级别：

```rust
async fn upstream_peer(
    &self,
    session: &mut Session,
    _ctx: &mut (),
) -> pingora::Result<Box<HttpPeer>> {
    if let Some(c) = session
        .downstream_modules_ctx
        .get_mut::<ResponseCompression>()
    {
        c.adjust_algorithm_level(Algorithm::Zstd, 6);
        c.adjust_algorithm_level(Algorithm::Brotli, 6);
        c.adjust_algorithm_level(Algorithm::Gzip, 9);
    }

    let value: u8 = rand::random();
    // 随机选择对应的upstream节点
    let addr = if value % 2 == 0 {
        "127.0.0.1:5000"
    } else {
        "127.0.0.1:5001"
    };
    let peer = Box::new(HttpPeer::new(addr, false, "".to_string()));
    Ok(peer)
}
```

### 设置服务线程数

`http_proxy_service`创建的服务，默认未指定线程数，对应的是pingora实例初始化时设置的值，建议针对每个服务指定其线程数，代码如下：

```rust
let mut lb = http_proxy_service(conf, self);
lb.threads = Some(4);
```

### 服务发现

pingora默认只提供了静态IP的形式，而在实现使用中，如果upstream是域名且ip会变，则需要实现基于dns的服务发现，`ServiceDiscovery`的实现也比较简单，只需要返回对应BTreeSet与以healthy的hashmap即可。

```rust
#[async_trait]
pub trait ServiceDiscovery {
    /// Return the discovered collection of backends.
    /// And *optionally* whether these backends are enabled to serve or not in a `HashMap`. Any backend
    /// that is not explicitly in the set is considered enabled.
    async fn discover(&self) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)>;
}
```

下面为一个简单基于dns的服务发现代码：

```rust
struct Dns {
    hosts: Vec<String>,
}

impl Dns {
    fn new(hosts: &[String]) -> Self {
        Self {
            hosts: hosts.to_vec(),
        }
    }
}

#[async_trait]
impl ServiceDiscovery for Dns {
    async fn discover(&self) -> pingora::Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        let mut upstreams = BTreeSet::new();
        let mut backends = vec![];
        // 将域名解析为对应ip
        for host in self.hosts.iter() {
            for addr in host.to_socket_addrs().unwrap() {
                backends.push(Backend {
                    addr: SocketAddr::Inet(addr),
                    weight: 1,
                });
            }
        }
        upstreams.extend(backends);
        // 也可提前先做一次health check
        // 已准备就绪的列表，则设置对应的值
        let health = HashMap::new();
        Ok((upstreams, health))
    }
}
```
