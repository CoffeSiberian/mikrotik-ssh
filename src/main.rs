#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use native_dialog::{MessageDialog, MessageType};
use ssh2::Session;
use std::env;
use std::net::TcpStream;

fn make_session(
    ip: &str,
    port: &str,
    user: &str,
    pass: &str,
) -> Result<Session, Box<dyn std::error::Error>> {
    let tcp = TcpStream::connect(format!("{}:{}", ip, port))?;
    let mut sess = Session::new()?;

    sess.set_tcp_stream(tcp);
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

    let sess = make_session(&host, &port, &user, &pass)?;
    if !sess.authenticated() {
        show_alert("Error: No se pudo autenticar con el servidor", MessageType::Error);
        return Ok(());
    }
    let mut channel = sess.channel_session()?;

    if enable_block {
        channel.exec(
            "/ip firewall filter set [find comment=\"Bloqueo Internet LAB 3\"] disabled=no",
        )?;
        show_alert("Filtro de bloqueo de internet activado", MessageType::Info);
    } else {
        channel.exec(
            "/ip firewall filter set [find comment=\"Bloqueo Internet LAB 3\"] disabled=yes",
        )?;
        show_alert("Filtro de bloqueo de internet desactivado", MessageType::Info);
    }

    Ok(())
}
