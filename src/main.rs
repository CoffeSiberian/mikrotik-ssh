#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use native_dialog::{MessageDialog, MessageType};
use ssh2::Session;
use std::env;
use std::net::TcpStream;
use std::sync::mpsc;
use std::time::Duration;

const SSH_TIMEOUT_SECS: u64 = 10;
// Extra seconds added on top of the SSH timeout to allow the SSH layer to
// return its own timeout error before the channel receiver gives up.
const SSH_GRACE_PERIOD_SECS: u64 = 2;

fn make_session(
    ip: &str,
    port: &str,
    user: &str,
    pass: &str,
) -> Result<Session, Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("{}:{}", ip, port);
    let tcp = TcpStream::connect_timeout(&addr.parse()?, Duration::from_secs(SSH_TIMEOUT_SECS))?;
    let mut sess = Session::new()?;

    sess.set_tcp_stream(tcp);
    sess.set_timeout((SSH_TIMEOUT_SECS * 1000) as u32);
    sess.handshake()?;
    sess.userauth_password(user, pass)?;

    Ok(sess)
}

fn load_env() -> (&'static str, &'static str, &'static str, &'static str) {
    let host = env!("MT_SSH_HOST");
    let port = env!("MT_SSH_PORT");
    let user = env!("MT_SSH_USER");
    let pass = env!("MT_SSH_PASS");

    return (host, port, user, pass);
}

fn show_confirm(message: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let result = MessageDialog::new()
        .set_title("MikroTik SSH")
        .set_text(message)
        .set_type(MessageType::Info)
        .show_confirm()?;

    Ok(result)
}

fn show_alert(message: &str, msg_type: MessageType) {
    let result = MessageDialog::new()
        .set_title("MikroTik SSH")
        .set_text(message)
        .set_type(msg_type)
        .show_alert();

    if let Err(e) = result {
        eprintln!("{}", message);
        eprintln!("Error al mostrar el diálogo: {}", e);
    }
}

fn main() {
    if let Err(e) = run() {
        show_alert(&format!("Error: {}", e), MessageType::Error);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let (host, port, user, pass) = load_env();

    let enable_block = show_confirm("¿Activar el bloqueo de internet?")?;

    // Show loading modal in a background thread while SSH connects.
    // The thread is intentionally not joined: when run() returns and main()
    // exits, the process terminates and the dialog is automatically closed.
    std::thread::spawn(|| {
        show_alert(
            "Conectando al servidor MikroTik...\nPor favor espere (máximo 10 segundos).",
            MessageType::Info,
        );
    });

    // Run the SSH connection and command in a separate thread
    let (tx, rx) = mpsc::channel::<Result<bool, String>>();
    std::thread::spawn(move || {
        let result = (|| -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
            let sess = make_session(host, port, user, pass)?;
            if !sess.authenticated() {
                return Err("No se pudo autenticar con el servidor".into());
            }
            let mut channel = sess.channel_session()?;
            if enable_block {
                channel.exec(
                    "/ip firewall filter set [find comment=\"Bloqueo Internet LAB 3\"] disabled=no",
                )?;
            } else {
                channel.exec(
                    "/ip firewall filter set [find comment=\"Bloqueo Internet LAB 3\"] disabled=yes",
                )?;
            }
            Ok(enable_block)
        })();
        tx.send(result.map_err(|e| e.to_string())).ok();
    });

    // Wait for the SSH thread with a slightly longer timeout than the SSH timeout itself
    match rx.recv_timeout(Duration::from_secs(SSH_TIMEOUT_SECS + SSH_GRACE_PERIOD_SECS)) {
        Ok(Ok(blocked)) => {
            if blocked {
                show_alert("Filtro de bloqueo de internet activado", MessageType::Info);
            } else {
                show_alert("Filtro de bloqueo de internet desactivado", MessageType::Info);
            }
        }
        Ok(Err(e)) => {
            show_alert(&format!("Error: {}", e), MessageType::Error);
        }
        Err(_) => {
            show_alert(
                "Error: Tiempo de espera agotado. No se pudo conectar al servidor.",
                MessageType::Error,
            );
        }
    }

    Ok(())
}
