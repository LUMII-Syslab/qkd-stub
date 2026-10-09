//! Desktop dashboard: shows the saved configuration and hosts the endpoint in-process,
//! so client activity can be shown live. Provisioning stays in the `qkd-stub` CLI.
#![cfg_attr(windows, windows_subsystem = "windows")]

use axum_server::Handle;
use clap::Parser;
use eframe::egui::{self, Color32, RichText};
use qkd_stub::{
    events::{self, Event},
    server,
    setup::{self, CertInfo, CheckItem, SaeEntry, Settings},
};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    path::PathBuf,
    sync::mpsc::{self, Receiver, Sender},
    time::Duration,
};

const MAX_EVENTS: usize = 1000;

#[derive(Parser)]
#[command(version, about = "Dashboard for a QKD stub endpoint")]
struct Args {
    /// Saved configuration, as created by `qkd-stub configure` or `qkd-stub demo init`.
    #[arg(long, default_value = "qkd-stub-data/config.toml")]
    config: PathBuf,
    /// Start serving immediately if the local setup checks pass.
    #[arg(long)]
    start: bool,
}

fn main() {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error) => {
            // A windowed process has no console, so show the text in a dialog.
            report_failure(&error.to_string());
            std::process::exit(if error.use_stderr() { 2 } else { 0 });
        }
    };
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        report_failure("could not install TLS crypto provider");
        std::process::exit(1);
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("QKD stub")
            .with_inner_size([860.0, 560.0]),
        ..Default::default()
    };
    if let Err(error) = eframe::run_native(
        "QKD stub",
        options,
        Box::new(move |cc| {
            let mut dashboard = Dashboard::new(args.config)?;
            if args.start {
                dashboard.start(&cc.egui_ctx);
            }
            Ok(Box::new(dashboard))
        }),
    ) {
        report_failure(&format!("cannot open the window: {error}"));
        std::process::exit(1);
    }
}

/// Everything shown from provisioning files. Contains no private key material.
struct Snapshot {
    settings: Settings,
    checks: Vec<CheckItem>,
    server_certs: Result<Vec<CertInfo>, String>,
    cas: Result<Vec<CertInfo>, String>,
    saes: Result<Vec<SaeEntry>, String>,
}

impl Snapshot {
    fn load(path: &std::path::Path) -> Result<Self, String> {
        let settings = Settings::load(path)
            .map_err(|e| e.to_string())?
            .resolved(path);
        let text = |e: Box<dyn std::error::Error>| e.to_string();
        Ok(Self {
            checks: setup::check_report(&settings),
            server_certs: setup::server_certificates(&settings).map_err(text),
            cas: setup::trusted_cas(&settings).map_err(text),
            saes: setup::sae_entries(&settings).map_err(text),
            settings,
        })
    }
    fn ready(&self) -> bool {
        self.checks.iter().all(|c| c.result.is_ok())
    }
}

enum State {
    Stopped,
    Starting,
    Running(SocketAddr),
    Stopping,
}

enum Message {
    Listening(SocketAddr),
    Ended(Result<(), String>),
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Status,
    Saes,
    Certificates,
    Activity,
}

struct Dashboard {
    runtime: Option<tokio::runtime::Runtime>,
    path_input: String,
    path: PathBuf,
    snapshot: Result<Snapshot, String>,
    state: State,
    last_error: Option<String>,
    handle: Option<Handle<SocketAddr>>,
    messages: Receiver<Message>,
    message_sender: Sender<Message>,
    event_receiver: Receiver<Event>,
    event_sender: Sender<Event>,
    log: VecDeque<Event>,
    total: u64,
    tab: Tab,
}

impl Dashboard {
    fn new(path: PathBuf) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (message_sender, messages) = mpsc::channel();
        let (event_sender, event_receiver) = mpsc::channel();
        Ok(Self {
            runtime: Some(
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()?,
            ),
            path_input: path.display().to_string(),
            snapshot: Snapshot::load(&path),
            path,
            state: State::Stopped,
            last_error: None,
            handle: None,
            messages,
            message_sender,
            event_receiver,
            event_sender,
            log: VecDeque::new(),
            total: 0,
            tab: Tab::Status,
        })
    }

    fn reload(&mut self) {
        self.path = PathBuf::from(self.path_input.trim());
        self.snapshot = Snapshot::load(&self.path);
    }

    fn start(&mut self, ctx: &egui::Context) {
        let Ok(snapshot) = &self.snapshot else { return };
        if !snapshot.ready() || !matches!(self.state, State::Stopped) {
            return;
        }
        let settings = snapshot.settings.clone();
        let runtime = self.runtime.as_ref().expect("runtime exists until exit");
        let handle = Handle::new();
        let (sender, mut receiver) = events::channel();
        self.last_error = None;
        self.state = State::Starting;
        self.handle = Some(handle.clone());

        let (messages, repaint) = (self.message_sender.clone(), ctx.clone());
        let listening = handle.clone();
        runtime.spawn(async move {
            if let Some(address) = listening.listening().await {
                let _ = messages.send(Message::Listening(address));
                repaint.request_repaint();
            }
        });
        let (messages, repaint) = (self.message_sender.clone(), ctx.clone());
        let served = handle.clone();
        runtime.spawn(async move {
            let result = server::serve(settings, served, Some(sender))
                .await
                .map_err(|e| e.to_string());
            let _ = messages.send(Message::Ended(result));
            repaint.request_repaint();
        });
        let (forward, repaint) = (self.event_sender.clone(), ctx.clone());
        runtime.spawn(async move {
            loop {
                match receiver.recv().await {
                    Ok(event) => {
                        if forward.send(event).is_err() {
                            break;
                        }
                        repaint.request_repaint();
                    }
                    Err(events::RecvError::Lagged(_)) => {}
                    Err(events::RecvError::Closed) => break,
                }
            }
        });
    }

    fn stop(&mut self) {
        if let Some(handle) = &self.handle {
            handle.graceful_shutdown(Some(Duration::from_secs(5)));
            self.state = State::Stopping;
        }
    }

    fn poll(&mut self) {
        while let Ok(message) = self.messages.try_recv() {
            match message {
                Message::Listening(address) => {
                    if matches!(self.state, State::Starting) {
                        self.state = State::Running(address);
                    }
                }
                Message::Ended(result) => {
                    self.last_error = result.err();
                    self.state = State::Stopped;
                    self.handle = None;
                }
            }
        }
        while let Ok(event) = self.event_receiver.try_recv() {
            self.total += 1;
            if self.log.len() == MAX_EVENTS {
                self.log.pop_front();
            }
            self.log.push_back(event);
        }
    }

    fn status_tab(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let mut start = false;
        let mut stop = false;
        let mut open_activity = false;
        match &self.snapshot {
            Err(error) => {
                ui.colored_label(Color32::LIGHT_RED, error);
                ui.label(
                    "Provision first with `qkd-stub configure` or `qkd-stub demo init`, \
                     then reload. Demo configurations are qkd-demo/a.toml and qkd-demo/b.toml.",
                );
            }
            Ok(snapshot) => {
                let s = &snapshot.settings;
                egui::Grid::new("settings").num_columns(2).show(ui, |ui| {
                    ui.label("Listen address");
                    ui.label(s.listen.to_string());
                    ui.end_row();
                    ui.label("KME ID");
                    ui.label(&s.kme_id);
                    ui.end_row();
                    ui.label("Peer KME ID");
                    ui.label(&s.peer_kme_id);
                    ui.end_row();
                    ui.label("Server certificate");
                    ui.label(s.tls_cert.display().to_string());
                    ui.end_row();
                    ui.label("Trusted client CAs");
                    ui.label(s.tls_client_ca.display().to_string());
                    ui.end_row();
                    ui.label("SAE registry");
                    ui.label(s.sae_map.display().to_string());
                    ui.end_row();
                    ui.label("Shared PSK file");
                    ui.label(s.psk_file.display().to_string());
                    ui.end_row();
                });
                ui.separator();
                ui.heading("Checks");
                for check in &snapshot.checks {
                    match &check.result {
                        Ok(()) => {
                            ui.colored_label(Color32::LIGHT_GREEN, format!("OK  {}", check.name))
                        }
                        Err(error) => ui.colored_label(
                            Color32::LIGHT_RED,
                            format!("INVALID  {}: {error}", check.name),
                        ),
                    };
                }
                ui.label(
                    "Peer PSK and SAE code agreement and CA chain trust are not checked here.",
                );
                ui.separator();
                ui.horizontal(|ui| {
                    match self.state {
                        State::Stopped => {
                            if ui
                                .add_enabled(snapshot.ready(), egui::Button::new("Start"))
                                .clicked()
                            {
                                start = true;
                            }
                            ui.label("Stopped");
                        }
                        State::Starting => {
                            ui.add_enabled(false, egui::Button::new("Starting…"));
                        }
                        State::Running(address) => {
                            if ui.button("Stop").clicked() {
                                stop = true;
                            }
                            ui.colored_label(
                                Color32::LIGHT_GREEN,
                                format!("Serving https://{address}"),
                            );
                            if ui.link("Show activity").clicked() {
                                open_activity = true;
                            }
                        }
                        State::Stopping => {
                            ui.add_enabled(false, egui::Button::new("Stopping…"));
                        }
                    };
                });
            }
        }
        if let Some(error) = &self.last_error {
            ui.colored_label(Color32::LIGHT_RED, format!("Server stopped: {error}"));
        }
        if start {
            self.start(&ctx);
        }
        if stop {
            self.stop();
        }
        if open_activity {
            self.tab = Tab::Activity;
        }
    }

    fn saes_tab(&self, ui: &mut egui::Ui) {
        let Ok(snapshot) = &self.snapshot else {
            ui.label("No configuration loaded.");
            return;
        };
        match &snapshot.saes {
            Err(error) => {
                ui.colored_label(Color32::LIGHT_RED, error);
            }
            Ok(saes) if saes.is_empty() => {
                ui.label("No SAEs configured. Use `qkd-stub sae add`.");
            }
            Ok(saes) => {
                egui::Grid::new("saes").striped(true).show(ui, |ui| {
                    for title in ["SAE ID", "Code", "Certificate identity selectors"] {
                        ui.label(RichText::new(title).strong());
                    }
                    ui.end_row();
                    for sae in saes {
                        ui.label(&sae.id);
                        ui.label(sae.code.to_string());
                        if sae.identities.is_empty() {
                            ui.label("remote only (no local certificate)");
                        } else {
                            ui.label(sae.identities.join("\n"));
                        }
                        ui.end_row();
                    }
                });
            }
        }
    }

    fn certificates_tab(&self, ui: &mut egui::Ui) {
        let Ok(snapshot) = &self.snapshot else {
            ui.label("No configuration loaded.");
            return;
        };
        egui::ScrollArea::vertical().show(ui, |ui| {
            for (title, list) in [
                ("Server certificate chain", &snapshot.server_certs),
                ("Trusted client CAs", &snapshot.cas),
            ] {
                ui.heading(title);
                match list {
                    Err(error) => {
                        ui.colored_label(Color32::LIGHT_RED, error);
                    }
                    Ok(list) if list.is_empty() => {
                        ui.label("None configured.");
                    }
                    Ok(list) => {
                        for (index, cert) in list.iter().enumerate() {
                            egui::CollapsingHeader::new(&cert.subject)
                                .id_salt((title, index))
                                .default_open(true)
                                .show(ui, |ui| {
                                    egui::Grid::new((title, index, "grid")).num_columns(2).show(
                                        ui,
                                        |ui| {
                                            ui.label("Issuer");
                                            ui.label(&cert.issuer);
                                            ui.end_row();
                                            ui.label("Valid");
                                            ui.label(format!(
                                                "{} to {}",
                                                cert.not_before, cert.not_after
                                            ));
                                            ui.end_row();
                                            ui.label("SHA-256");
                                            ui.monospace(&cert.sha256);
                                            ui.end_row();
                                        },
                                    );
                                });
                        }
                    }
                }
                ui.add_space(8.0);
            }
        });
    }

    fn activity_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("Clear").clicked() {
                self.log.clear();
            }
            ui.label(format!(
                "{} requests since the GUI started; showing the latest {}. Times are UTC.",
                self.total,
                self.log.len()
            ));
        });
        if !matches!(self.state, State::Running(_)) {
            ui.label("The server is not running; start it on the Status tab.");
        }
        ui.separator();
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                egui::Grid::new("activity").striped(true).show(ui, |ui| {
                    for title in ["Time", "Caller SAE", "Method", "Route", "Status", "ms"] {
                        ui.label(RichText::new(title).strong());
                    }
                    ui.end_row();
                    for event in &self.log {
                        ui.monospace(format!(
                            "{:02}:{:02}:{:02}",
                            event.time.hour(),
                            event.time.minute(),
                            event.time.second()
                        ));
                        ui.label(event.caller_sae.as_deref().unwrap_or("unauthenticated"));
                        ui.label(&event.method);
                        ui.label(&event.route);
                        let color = match event.status {
                            200..=299 => Color32::LIGHT_GREEN,
                            400..=499 => Color32::from_rgb(240, 180, 80),
                            _ => Color32::LIGHT_RED,
                        };
                        ui.colored_label(color, event.status.to_string());
                        ui.label(event.duration_ms.to_string());
                        ui.end_row();
                    }
                });
            });
    }
}

impl eframe::App for Dashboard {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll();
        egui::Panel::top("header").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Configuration");
                let editor =
                    ui.add(egui::TextEdit::singleline(&mut self.path_input).desired_width(380.0));
                let enter = editor.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                let running = !matches!(self.state, State::Stopped);
                if ui
                    .add_enabled(!running, egui::Button::new("Reload"))
                    .on_disabled_hover_text("Stop the server before changing configuration")
                    .clicked()
                    || (enter && !running)
                {
                    self.reload();
                }
            });
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Status, "Status");
                ui.selectable_value(&mut self.tab, Tab::Saes, "SAEs");
                ui.selectable_value(&mut self.tab, Tab::Certificates, "Certificates");
                ui.selectable_value(&mut self.tab, Tab::Activity, "Activity");
            });
        });
        egui::CentralPanel::default_margins().show(ui, |ui| match self.tab {
            Tab::Status => self.status_tab(ui),
            Tab::Saes => self.saes_tab(ui),
            Tab::Certificates => self.certificates_tab(ui),
            Tab::Activity => self.activity_tab(ui),
        });
    }
}

impl Drop for Dashboard {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            handle.graceful_shutdown(Some(Duration::from_secs(1)));
        }
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(Duration::from_secs(3));
        }
    }
}

#[cfg(windows)]
fn report_failure(message: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
    let wide = |text: &str| text.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let (text, title) = (wide(message), wide("QKD stub"));
    // SAFETY: both buffers are NUL-terminated and outlive the call.
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

#[cfg(not(windows))]
fn report_failure(message: &str) {
    eprintln!("{message}");
}
