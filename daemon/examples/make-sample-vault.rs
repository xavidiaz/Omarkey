//! Dev helper: write a small demo `.kdbx` for testing omarkeyd end to end.
//!
//!   cargo run --example make-sample-vault -- /tmp/demo.kdbx demopass
//!
//! Needs the `save_kdbx4` feature (on via dev-dependencies during `cargo run
//! --example`). Not built into the daemon.

use keepass::db::{Entry, Group, Value};
use keepass::{Database, DatabaseKey};

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| "/tmp/demo.kdbx".into());
    let password = args.next().unwrap_or_else(|| "demopass".into());

    let mut db = Database::new(Default::default());

    let mut dev = Group::new("Dev");
    dev.add_child(entry(
        "GitHub",
        "octocat",
        "https://github.com",
        "correct-horse-battery-staple",
        Some(
            "otpauth://totp/GitHub:octocat?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ\
&issuer=GitHub&algorithm=SHA1&digits=6&period=30",
        ),
    ));
    dev.add_child(entry(
        "GitLab",
        "octocat",
        "https://gitlab.com",
        "s3cr3t-gl",
        None,
    ));
    db.root.add_child(dev);

    db.root.add_child(entry(
        "Fastmail",
        "me@example.com",
        "https://fastmail.com",
        "swordfish-1998",
        None,
    ));

    let mut buf = Vec::new();
    db.save(&mut buf, DatabaseKey::new().with_password(&password))
        .expect("save");
    std::fs::write(&path, buf).expect("write");
    eprintln!("wrote {path} (password: {password})");
}

fn entry(title: &str, user: &str, url: &str, pass: &str, otp: Option<&str>) -> Entry {
    let mut e = Entry::new();
    e.fields
        .insert("Title".into(), Value::Unprotected(title.into()));
    e.fields
        .insert("UserName".into(), Value::Unprotected(user.into()));
    e.fields
        .insert("URL".into(), Value::Unprotected(url.into()));
    e.fields
        .insert("Password".into(), Value::Protected(pass.as_bytes().into()));
    if let Some(otp) = otp {
        e.fields
            .insert("otp".into(), Value::Protected(otp.as_bytes().into()));
    }
    e
}
