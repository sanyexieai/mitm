use chrono::Local;
use slint::SharedString;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::net::TcpListener;
use slint::{VecModel, Model};
use winreg::enums::*;
use winreg::RegKey;
use tokio::io::AsyncReadExt;
use std::sync::atomic::{AtomicBool, Ordering};
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, SanType};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::net::ToSocketAddrs;
use local_ip_address;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
slint::include_modules!();

// 从 Slint 生成的类型
use slint::ComponentHandle;

// 添加全局变量保存原始代理状态
static ORIGINAL_PROXY_ENABLED: AtomicBool = AtomicBool::new(false);
static ORIGINAL_PROXY_SERVER: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

// 修改代理设置函数
fn set_system_proxy(enable: bool, proxy_addr: Option<String>, save_original: bool) -> Result<(), Box<dyn std::error::Error>> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let internet_settings = hkcu.open_subkey_with_flags(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        KEY_READ | KEY_WRITE,
    )?;

    if save_original {
        // 保存原始状态
        let original_enabled: u32 = internet_settings.get_value("ProxyEnable")?;
        ORIGINAL_PROXY_ENABLED.store(original_enabled == 1, Ordering::SeqCst);
        if let Ok(original_server) = internet_settings.get_value("ProxyServer") {
            let mut server = ORIGINAL_PROXY_SERVER.lock().unwrap();
            *server = original_server;
        }
        println!("已保存原始代理状态");
    }

    if enable {
        internet_settings.set_value("ProxyEnable", &1u32)?;
        if let Some(addr) = proxy_addr.as_ref() {
            internet_settings.set_value("ProxyServer", addr)?;
            // 添加绕过地址列表
            internet_settings.set_value("ProxyOverride", &"localhost;127.*;10.*;172.16.*;192.168.*;*.local;<local>")?;
        }
        println!("系统代理已启用: {}", proxy_addr.as_deref().unwrap_or(""));
    } else {
        // 还原原始状态
        let original_enabled = if ORIGINAL_PROXY_ENABLED.load(Ordering::SeqCst) { 1u32 } else { 0u32 };
        internet_settings.set_value("ProxyEnable", &original_enabled)?;
        if original_enabled == 1 {
            let original_server = ORIGINAL_PROXY_SERVER.lock().unwrap();
            internet_settings.set_value("ProxyServer", &*original_server)?;
            println!("系统代理已还原: {}", original_server);
        } else {
            println!("系统代理已禁用");
        }
    }
    Ok(())
}

#[derive(Clone)]
struct Proxy {
    window: slint::Weak<MainWindow>,
    listener: Option<Arc<Mutex<TcpListener>>>,
    listen_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

fn generate_ca_certificate() -> Result<(Certificate, PathBuf), Box<dyn std::error::Error>> {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, "MITM Proxy CA");
    params.distinguished_name.push(DnType::OrganizationName, "MITM Proxy");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let cert = Certificate::from_params(params)?;
    
    // 保存证书到用户目录
    let cert_path = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("mitm-proxy")
        .join("ca.crt");

    fs::create_dir_all(cert_path.parent().unwrap())?;
    fs::write(&cert_path, cert.serialize_pem()?)?;

    Ok((cert, cert_path))
}

fn install_certificate(cert_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // 使用 Windows 证书工具安装证书
    let status = Command::new("certutil")
        .args(&["-addstore", "ROOT", cert_path.to_str().unwrap()])
        .status()?;

    if !status.success() {
        return Err("Failed to install certificate".into());
    }
    println!("证书已安装");
    Ok(())
}

fn check_and_install_certificate() -> Result<Certificate, Box<dyn std::error::Error>> {
    let cert_path = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("mitm-proxy")
        .join("ca.crt");

    let cert = if cert_path.exists() {
        let cert_pem = fs::read_to_string(&cert_path)?;
        let params = CertificateParams::new(vec!["MITM Proxy CA".to_string()]);
        Certificate::from_params(params)?
    } else {
        let (cert, path) = generate_ca_certificate()?;
        install_certificate(&path)?;
        cert
    };

    Ok(cert)
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    addr: SocketAddr,
    ca_cert: Arc<Certificate>,
    weak: slint::Weak<MainWindow>,
) -> Result<(), std::io::Error> {
    let start_time = Instant::now();
    let mut buffer = [0; 4096];
    let n = stream.peek(&mut buffer).await?;  // 只是peek，没有实际读取数据
    
    // 我们需要实际读取和转发数据
    let mut server_stream = None;
    
    let mut domain_info = String::new();
    let mut request_path = String::new();
    let mut method = String::new();
    let mut status = String::new();
    let mut app = String::new();
    let mut server_ip = String::new();
    
    // 检测是否是 TLS 连接
    let is_tls = n >= 3 && buffer[0] == 0x16 && buffer[1] == 0x03;
    
    if is_tls {
        if let Ok(hostname) = get_sni_hostname(&buffer[..n]) {
            domain_info = hostname.clone();
            if let Ok(mut addrs) = format!("{}:443", hostname).to_socket_addrs() {
                if let Some(addr) = addrs.next() {
                    server_ip = addr.ip().to_string();
                    println!("HTTPS 请求: {} -> {}", addr.ip(), hostname);
                    if let Ok(server) = tokio::net::TcpStream::connect(addr).await {
                        server_stream = Some(server);
                    }
                }
            }
            method = "HTTPS".to_string();
            status = "Established".to_string();
        }
    } else {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);
        
        if let Ok(parsed) = req.parse(&buffer[..n]) {
            if parsed.is_complete() {
                if let Some(m) = req.method {
                    method = m.to_string();
                }
                if let Some(host) = req.headers.iter().find(|h| h.name.eq_ignore_ascii_case("host")) {
                    domain_info = String::from_utf8_lossy(host.value).to_string();
                }
                if let Some(path) = req.path {
                    request_path = path.to_string();
                }
                if let Some(user_agent) = req.headers.iter().find(|h| h.name.eq_ignore_ascii_case("user-agent")) {
                    app = get_app_name(String::from_utf8_lossy(user_agent.value).as_ref());
                }
                status = "200 OK".to_string();  // 这里可以根据实际响应修改
            }
        }
    }

    // 读取完整的请求
    let mut request_data = Vec::new();
    stream.read_to_end(&mut request_data).await?;

    // 如果有服务器连接，转发请求并读取响应
    let response_data = if let Some(mut server) = server_stream {
        server.write_all(&request_data).await?;
        let mut response = Vec::new();
        server.read_to_end(&mut response).await?;
        response
    } else {
        Vec::new()
    };

    let duration = start_time.elapsed();
    
    // 更新 UI
    slint::invoke_from_event_loop(move || {
        if let Some(window) = weak.upgrade() {
            let current_requests = window.get_requests();
            let vec_model = current_requests.as_any()
                .downcast_ref::<VecModel<RequestInfo>>()
                .unwrap();
            let mut vec = (0..vec_model.row_count())
                .map(|i| vec_model.row_data(i).unwrap())
                .collect::<Vec<_>>();
            let request = RequestInfo {
                method: SharedString::from(method),
                url: SharedString::from(format!("{}{}", domain_info, request_path)),
                app: SharedString::from(app),
                status: SharedString::from(status),
                server_ip: SharedString::from(server_ip),
                duration: SharedString::from(format!("{:.2}s", duration.as_secs_f32())),
                size: SharedString::from(format!("{}B", n)),
                timestamp: SharedString::from(Local::now().format("%H:%M:%S").to_string()),
                raw_request: SharedString::from(String::from_utf8_lossy(&request_data).to_string()),
                request_headers: SharedString::from(format_headers(&request_data)),
                request_body: SharedString::from(get_request_body(&request_data)),
                raw_response: SharedString::from(String::from_utf8_lossy(&response_data).to_string()),
                response_headers: SharedString::from(format_headers(&response_data)),
                response_body: SharedString::from(get_request_body(&response_data)),
            };
            vec.push(request);
            window.set_requests(std::rc::Rc::new(VecModel::from(vec)).into());
        }
    }).unwrap();
    
    Ok(())
}

fn get_sni_hostname(data: &[u8]) -> Result<String, std::io::Error> {
    // 简单的 SNI 解析
    if data.len() < 5 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "数据太短"));
    }
    
    let mut pos = 5 + ((data[3] as usize) << 8 | data[4] as usize);
    if data.len() < pos + 4 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "数据不完整"));
    }
    
    while pos + 4 <= data.len() {
        let len = ((data[pos + 2] as usize) << 8) | data[pos + 3] as usize;
        if data[pos] == 0 {
            if let Ok(name) = String::from_utf8(data[pos + 4..pos + 4 + len].to_vec()) {
                return Ok(name);
            }
        }
        pos += 4 + len;
    }
    
    Err(std::io::Error::new(std::io::ErrorKind::Other, "未找到 SNI"))
}

// 添加辅助函数来识别应用程序
fn get_app_name(user_agent: &str) -> String {
    let user_agent = user_agent.to_lowercase();
    if user_agent.contains("chrome") {
        "Chrome".to_string()
    } else if user_agent.contains("firefox") {
        "Firefox".to_string()
    } else if user_agent.contains("safari") {
        "Safari".to_string()
    } else if user_agent.contains("edge") {
        "Edge".to_string()
    } else {
        "Unknown".to_string()
    }
}

// 添加辅助函数来格式化请求头
fn format_headers(data: &[u8]) -> String {
    let mut headers = String::new();
    if let Ok(str_data) = String::from_utf8_lossy(data).to_string().parse::<String>() {
        for line in str_data.lines() {
            if line.is_empty() {
                break;
            }
            headers.push_str(line);
            headers.push('\n');
        }
    }
    headers
}

fn get_request_body(data: &[u8]) -> String {
    if let Ok(str_data) = String::from_utf8_lossy(data).to_string().parse::<String>() {
        if let Some(idx) = str_data.find("\r\n\r\n") {
            return str_data[idx + 4..].to_string();
        }
    }
    String::new()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ca_cert = Arc::new(check_and_install_certificate()?);
    let window = MainWindow::new()?;
    
    let proxy = Arc::new(Mutex::new(Proxy {
        window: window.as_weak(),
        listener: None,
        listen_task: Arc::new(Mutex::new(None)),
    }));

    let proxy_clone = proxy.clone();
    let weak = window.as_weak();
    let ca_cert = ca_cert.clone();
    window.on_toggle_listening(move || {
        let proxy = proxy_clone.clone();
        let weak = weak.clone();
        let ca_cert = ca_cert.clone();
        
        let _ = slint::spawn_local(async move {
            let mut proxy = proxy.lock().await;
            if let Some(window) = weak.upgrade() {
                if window.get_is_listening() {
                    println!("正在停止监听...");
                    if let Some(task) = proxy.listen_task.lock().await.take() {
                        task.abort();
                        println!("已中止监听任务");
                    }
                    proxy.listener = None;
                    if let Err(e) = set_system_proxy(false, None, false) {
                        eprintln!("还原系统代理失败: {}", e);
                    }
                    window.set_is_listening(false);
                    println!("监听已停止");
                } else {
                    println!("正在启动监听...");
                    // 根据复选框状态决定监听地址
                    let ip = if window.get_listen_loopback() {
                        [0, 0, 0, 0]  // 监听所有地址，包括回环
                    } else {
                        match local_ip_address::local_ip() {
                            Ok(ip) => {
                                if let std::net::IpAddr::V4(ipv4) = ip {
                                    let octets = ipv4.octets();
                                    println!("使用IP地址: {}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
                                    octets
                                } else {
                                    eprintln!("不支持 IPv6，使用默认地址");
                                    [0, 0, 0, 0]
                                }
                            }
                            Err(_) => {
                                eprintln!("无法获取本地IP，使用默认地址");
                                [0, 0, 0, 0]
                            }
                        }
                    };
                    let addr = SocketAddr::from((ip, 8080));
                    match TcpListener::bind(addr).await {
                        Ok(listener) => {
                            println!("成功绑定端口 8080");
                            proxy.listener = Some(Arc::new(Mutex::new(listener)));
                            
                            // 设置系统代理时使用实际IP
                            let proxy_ip = if window.get_listen_loopback() {
                                "127.0.0.1".to_string()
                            } else {
                                match local_ip_address::local_ip() {
                                    Ok(ip) => ip.to_string(),
                                    Err(_) => "127.0.0.1".to_string(),
                                }
                            };
                            
                            if let Err(e) = set_system_proxy(true, Some(format!("{}:8080", proxy_ip)), true) {
                                eprintln!("启用系统代理失败: {}", e);
                            }
                            
                            window.set_is_listening(true);
                            println!("监听已启动");
                            
                            let listener = Arc::clone(proxy.listener.as_ref().unwrap());
                            let weak = window.as_weak();
                            let ca_cert = ca_cert.clone();
                            let task = tokio::spawn(async move {
                                loop {
                                    match listener.lock().await.accept().await {
                                        Ok((mut stream, addr)) => {
                                            println!("收到新的连接: {}", addr);
                                            
                                            // 处理连接
                                            let addr_clone = addr;
                                            let ca_cert = ca_cert.clone();
                                            let weak = weak.clone();  // 在这里克隆
                                            tokio::spawn(async move {
                                                if let Err(e) = handle_connection(stream, addr_clone, ca_cert, weak).await {
                                                    eprintln!("处理连接错误: {}", e);
                                                }
                                            });
                                        }
                                        Err(e) => {
                                            eprintln!("接受连接错误: {}", e);
                                            if e.kind() == std::io::ErrorKind::Other {
                                                break;
                                            }
                                        }
                                    }
                                }
                            });
                            proxy.listen_task.lock().await.replace(task);
                        }
                        Err(e) => {
                            eprintln!("无法启动监听: {}", e);
                            window.set_is_listening(false);
                        }
                    }
                }
            }
        });
    });

    window.run()?;
    Ok(())
}