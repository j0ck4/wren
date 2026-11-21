//! Bridge to the host's `wireguard-tools`.
//!
//! Wren runs inside a Flatpak sandbox, so every command is executed
//! on the host via `flatpak-spawn --host`. Privileged commands go
//! through `pkexec`, which presents a polkit prompt.
//!
//! Ubuntu 26.04 confines `wg-quick` to reading configs
//! under `/etc/wireguard`, so connect/disconnect run `wren-tunnel.sh`
//! as root: it copies the config (fed via stdin, keeping the private
//! key out of argv) into `/etc/wireguard` for the tunnel's lifetime.

// `args` (the command words) and `argv` (the full flatpak-spawn argv)
// are deliberately distinct here.
#![allow(clippy::similar_names)]

use std::{collections::HashSet, ffi::OsStr, fs, path::Path};

use anyhow::{Context, Result, bail};
use gtk::{gio, glib};

const TUNNEL_HELPER: &str = include_str!("wren-tunnel.sh");

pub async fn up(config_path: &Path) -> Result<()> {
    tunnel("up", config_path).await
}

pub async fn down(config_path: &Path) -> Result<()> {
    tunnel("down", config_path).await
}

async fn tunnel(action: &str, config_path: &Path) -> Result<()> {
    let name = config_path
        .file_stem()
        .and_then(OsStr::to_str)
        .with_context(|| format!("no tunnel name in {}", config_path.display()))?;
    let config = fs::read_to_string(config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    // pkexec shows the full command line in its password prompt, so the
    // helper travels over stdin ahead of the config, NUL-separated.
    let mut input = Vec::with_capacity(TUNNEL_HELPER.len() + 1 + config.len());
    input.extend_from_slice(TUNNEL_HELPER.as_bytes());
    input.push(0);
    input.extend_from_slice(config.as_bytes());
    let args = [
        "pkexec",
        "/usr/bin/bash",
        "-c",
        r#"read -rd '' s && eval "$s""#,
        "wren-tunnel",
        action,
        name,
    ];
    let proc = spawn(&args, gio::SubprocessFlags::STDIN_PIPE)?;
    let (_, err) = proc
        .communicate_future(Some(&glib::Bytes::from_owned(input)))
        .await
        .context("waiting for host command")?;
    if !proc.is_successful() {
        let err = err.map(|b| String::from_utf8_lossy(&b).into_owned());
        bail!(
            "wg-quick {action} {name} failed: {}",
            err.unwrap_or_default().trim()
        );
    }
    Ok(())
}

/// Reads the cumulative byte counters for a wireguard interface.
/// Returned as `(received, sent)`. `/sys/class/net/<iface>/statistics`
/// is world-readable, so this avoids any pkexec prompt.
pub async fn transfer(name: &str) -> Result<(u64, u64)> {
    let rx_path = format!("/sys/class/net/{name}/statistics/rx_bytes");
    let tx_path = format!("/sys/class/net/{name}/statistics/tx_bytes");
    let out = capture(&["cat", &rx_path, &tx_path]).await?;
    let mut lines = out.lines();
    let rx: u64 = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing rx line"))?
        .trim()
        .parse()
        .context("parsing rx_bytes")?;
    let tx: u64 = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing tx line"))?
        .trim()
        .parse()
        .context("parsing tx_bytes")?;
    Ok((rx, tx))
}

/// Returns the set of WireGuard interface names that currently
/// exist on the host. Uses `ip link show type wireguard`, which is
/// unprivileged and ignores unrelated devices like `docker0` or
/// `lo`.
pub async fn active_interfaces() -> Result<HashSet<String>> {
    let out = capture(&["ip", "-br", "link", "show", "type", "wireguard"]).await?;
    Ok(out
        .lines()
        .filter_map(|line| {
            let first = line.split_whitespace().next()?;
            // `ip -br` may show names like "veth0@if12" for paired
            // devices; strip the `@parent` suffix just in case.
            let name = first.split('@').next().unwrap_or(first);
            (!name.is_empty()).then(|| name.to_string())
        })
        .collect())
}

fn spawn(args: &[&str], extra: gio::SubprocessFlags) -> Result<gio::Subprocess> {
    gio::Subprocess::newv(&host_argv(args), flags() | extra).context("spawning host command")
}

async fn capture(args: &[&str]) -> Result<String> {
    let proc = spawn(args, gio::SubprocessFlags::NONE)?;
    let (out, err) = proc
        .communicate_utf8_future(None)
        .await
        .context("waiting for host command")?;
    if !proc.is_successful() {
        bail!(
            "{} failed: {}",
            args.join(" "),
            err.map(|s| s.to_string()).unwrap_or_default().trim()
        );
    }
    Ok(out.map(|s| s.to_string()).unwrap_or_default())
}

fn host_argv<'a>(args: &'a [&'a str]) -> Vec<&'a OsStr> {
    let mut argv: Vec<&OsStr> = Vec::with_capacity(args.len() + 2);
    argv.push(OsStr::new("flatpak-spawn"));
    argv.push(OsStr::new("--host"));
    argv.extend(args.iter().map(|s| OsStr::new(*s)));
    argv
}

fn flags() -> gio::SubprocessFlags {
    gio::SubprocessFlags::STDOUT_PIPE | gio::SubprocessFlags::STDERR_PIPE
}
