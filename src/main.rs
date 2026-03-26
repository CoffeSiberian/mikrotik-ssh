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

fn show_confirm(message: &str) -> bool {
    MessageDialog::new()
        .set_title("MikroTik SSH")
        .set_text(message)
        .set_type(MessageType::Info)
        .show_confirm()
        .unwrap_or(false)
}

fn show_alert(message: &str, msg_type: MessageType) {
    MessageDialog::new()
        .set_title("MikroTik SSH")
        .set_text(message)
        .set_type(msg_type)
        .show_alert()
        .unwrap_or(());
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (host, port, user, pass) = load_env();

    let disable = show_confirm("¿Desactivar el filtro de bloqueo de internet?");

    let sess = make_session(&host, &port, &user, &pass)?;
    if !sess.authenticated() {
        show_alert("Error: No se pudo autenticar con el servidor", MessageType::Error);
        return Ok(());
    }
    let mut channel = sess.channel_session()?;

    if disable {
        channel.exec(
            "/ip firewall filter set [find comment=\"Bloqueo Internet LAB 3\"] disabled=yes",
        )?;
        show_alert("Filtro de bloqueo de internet desactivado", MessageType::Info);
    } else {
        channel.exec(
            "/ip firewall filter set [find comment=\"Bloqueo Internet LAB 3\"] disabled=no",
        )?;
        show_alert("Filtro de bloqueo de internet activado", MessageType::Info);
    }

    Ok(())
}
