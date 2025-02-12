use chrono::Local;
use slint::SharedString;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use slint::{VecModel, Model, ComponentHandle};
use winreg::enums::*;
use winreg::RegKey;
use std::sync::atomic::{AtomicBool, Ordering};
use std::net::ToSocketAddrs;
use local_ip_address;
use std::time::{Instant, Duration};
use tokio::io::AsyncWriteExt;
use hudsucker::{
    certificate_authority::RcgenAuthority,
    HttpContext, HttpHandler, WebSocketHandler, WebSocketContext,
    builder::ProxyBuilder,
    Body, RequestOrResponse,
    Proxy,
};
use http::{Request, Response};
use tokio_tungstenite::tungstenite::Message;
use async_trait::async_trait;
use tracing::*;

slint::include_modules!();

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
struct ProxyState {
    window: slint::Weak<MainWindow>,
    listen_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

#[derive(Clone)]
struct ProxyHandler {
    weak: slint::Weak<MainWindow>,
    start_time: std::time::Instant,
}

#[async_trait::async_trait]
impl HttpHandler for ProxyHandler {
    async fn handle_request(
        &mut self,
        ctx: &HttpContext,
        req: Request<Body>,
    ) -> hudsucker::RequestOrResponse {
        let method = req.method().to_string();
        let url = req.uri().to_string();
        let host = req.uri().host().unwrap_or("unknown").to_string();
        let headers = format!("{:?}", req.headers());
        
        // 更新UI
        let weak = self.weak.clone();
        let request_info = RequestInfo {
            method: method.into(),
            url: url.into(),
            app: get_app_name(req.headers().get("user-agent")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("Unknown")).into(),
            status: "Pending".into(),
            server_ip: host.into(),
            duration: "0.00s".into(),
            size: "0B".into(),
            timestamp: Local::now().format("%H:%M:%S").to_string().into(),
            raw_request: format!("{:?}", req).into(),
            request_headers: headers.into(),
            request_body: "".into(),
            raw_response: "".into(),
            response_headers: "".into(),
            response_body: "".into(),
        };
        
        slint::invoke_from_event_loop(move || {
            if let Some(window) = weak.upgrade() {
                let current_requests = window.get_requests();
                let vec_model = current_requests.as_any()
                    .downcast_ref::<VecModel<RequestInfo>>()
                    .unwrap();
                let mut vec = (0..vec_model.row_count())
                    .map(|i| vec_model.row_data(i).unwrap())
                    .collect::<Vec<_>>();
                vec.push(request_info);
                window.set_requests(std::rc::Rc::new(VecModel::from(vec)).into());
            }
        }).unwrap();

        req.into()
    }

    async fn handle_response(
        &mut self,
        ctx: &HttpContext,
        res: Response<Body>,
    ) -> Response<Body> {
        let duration = self.start_time.elapsed();
        let status = res.status().to_string();
        let headers = format!("{:?}", res.headers());
        
        // 更新状态等信息
        let weak = self.weak.clone();
        slint::invoke_from_event_loop(move || {
            if let Some(window) = weak.upgrade() {
                // 更新最后一个请求的状态
                let current_requests = window.get_requests();
                let vec_model = current_requests.as_any()
                    .downcast_ref::<VecModel<RequestInfo>>()
                    .unwrap();
                if let Some(mut last_request) = vec_model.row_data(vec_model.row_count() - 1) {
                    last_request.status = status.into();
                    last_request.duration = format!("{:.2}s", duration.as_secs_f32()).into();
                    last_request.response_headers = headers.into();
                    // 更新模型
                    let mut vec = (0..vec_model.row_count() - 1)
                        .map(|i| vec_model.row_data(i).unwrap())
                        .collect::<Vec<_>>();
                    vec.push(last_request);
                    window.set_requests(std::rc::Rc::new(VecModel::from(vec)).into());
                }
            }
        }).unwrap();

        res
    }
}

impl WebSocketHandler for ProxyHandler {
    async fn handle_message(&mut self, _ctx: &WebSocketContext, msg: Message) -> Option<Message> {
        println!("WebSocket消息: {:?}", msg);
        Some(msg)
    }
}

fn get_app_name(user_agent: &str) -> String {
    let ua = user_agent.to_lowercase();
    if ua.contains("chrome") {
        "Chrome".to_string()
    } else if ua.contains("firefox") {
        "Firefox".to_string()
    } else if ua.contains("safari") {
        "Safari".to_string()
    } else if ua.contains("edge") {
        "Edge".to_string()
    } else {
        "Unknown".to_string()
    }
}

async fn start_proxy(weak: slint::Weak<MainWindow>, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let ca = RcgenAuthority::new(
        "MITM Proxy CA",
        "MITM Proxy",
        vec!["MITM Proxy Root CA".to_string()],
        Duration::from_secs(365 * 24 * 60 * 60),
    )?;

    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_ca(ca)
        .with_http_handler(ProxyHandler { 
            weak,
            start_time: std::time::Instant::now(),
        })
        .with_websocket_handler(ProxyHandler { 
            weak: weak.clone(),
            start_time: std::time::Instant::now(),
        })
        .build()?;

    proxy.start().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let window = MainWindow::new()?;
    
    let proxy = Arc::new(Mutex::new(ProxyState {
        window: window.as_weak(),
        listen_task: Arc::new(Mutex::new(None)),
    }));

    let proxy_clone = proxy.clone();
    let weak = window.as_weak();
    window.on_toggle_listening(move || {
        let proxy = proxy_clone.clone();
        let weak = weak.clone();
        
        let _ = slint::spawn_local(async move {
            let mut proxy = proxy.lock().await;
            if let Some(window) = weak.upgrade() {
                if window.get_is_listening() {
                    println!("正在停止监听...");
                    if let Some(task) = proxy.listen_task.lock().await.take() {
                        task.abort();
                        println!("已中止监听任务");
                    }
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
                    
                    let weak = window.as_weak();
                    let task = tokio::spawn(async move {
                        if let Err(e) = start_proxy(weak, addr).await {
                            eprintln!("代理错误: {}", e);
                        }
                    });
                    
                    proxy.listen_task.lock().await.replace(task);
                    
                    window.set_is_listening(true);
                    println!("监听已启动");
                }
            }
        });
    });

    window.run()?;
    Ok(())
}