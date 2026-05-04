//! dm-cli — 3-terminal chat demo. Each terminal prints its npub/nsec at startup.
//! Commands:
//!   /create <npub> <npub>        — create a group with two other members
//!   /send <text>                  — send to the current (only) group
//!   /members                      — list members of current group
//!   /status                       — show key info
//!   /quit                         — exit

use std::io::Write;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{broadcast, Mutex};

use cgka_engine::{Capability, FeatureStatus, GroupEvent, GroupId};
use nostr::key::{Keys, SecretKey};
use nostr::nips::nip19::ToBech32;
use whitenoise_core_spike::{parse_npub, Session};

const RELAY: &str = "wss://relay.primal.net";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dm_cli=info,whitenoise_core_spike=info".into()),
        )
        .init();

    // Identity: nsec from env, or generate fresh.
    let keys = match std::env::var("DM_NSEC") {
        Ok(nsec) => Keys::parse(&nsec).map_err(|e| anyhow!("bad DM_NSEC: {e:?}"))?,
        Err(_) => Keys::generate(),
    };

    let npub = keys.public_key().to_bech32().unwrap_or_else(|_| "?".into());
    let nsec = keys.secret_key().to_bech32().unwrap_or_else(|_| "?".into());

    println!("═════════════════════════════════════════════════════════");
    println!(" dm-cli — marmot stack spike");
    println!(" npub: {npub}");
    println!(" nsec: {nsec}   (reuse with DM_NSEC=... to keep identity)");
    println!(" relay: {RELAY}");
    println!("═════════════════════════════════════════════════════════");
    println!();

    // Honor DM_DROP_CAPS=selfremove to advertise a KeyPackage that omits the
    // SelfRemove capability. Lets us drive the negative capability-negotiation
    // test: any group that Requires SelfRemove will refuse to add this client.
    let dropped_caps = match std::env::var("DM_DROP_CAPS") {
        Ok(s) => s
            .split(',')
            .filter_map(|t| match t.trim().to_ascii_lowercase().as_str() {
                "selfremove" => Some(Capability::Proposal(0x000a)),
                "" => None,
                other => {
                    eprintln!("warning: unknown DM_DROP_CAPS token '{other}' ignored");
                    None
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    if !dropped_caps.is_empty() {
        println!(" DM_DROP_CAPS active — advertising KeyPackage missing: {:?}", dropped_caps);
    }

    let session = Session::new_with_dropped_caps(
        clone_secret(keys.secret_key()),
        vec![RELAY.to_string()],
        dropped_caps,
    )
    .await?;
    println!("[connected + key package published]");
    println!();

    let session = Arc::new(session);
    let current_group: Arc<Mutex<Option<GroupId>>> = Arc::new(Mutex::new(None));

    // Event printer loop.
    let mut events = session.subscribe_events();
    let cg_clone = current_group.clone();
    let my_pk_bytes = session.public_key().to_bytes();
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(ev) => {
                    print_event(&ev, &cg_clone, my_pk_bytes).await;
                    print_prompt();
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    eprintln!("[events lagged {n}]");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // REPL.
    print_help();
    print_prompt();
    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = stdin.next_line().await? {
        let trimmed = line.trim().to_string();
        if trimmed.is_empty() {
            print_prompt();
            continue;
        }
        if let Err(e) = handle_command(&trimmed, &session, &current_group).await {
            println!("error: {e:?}");
        }
        print_prompt();
    }

    Ok(())
}

fn clone_secret(s: &SecretKey) -> SecretKey {
    // SecretKey is Clone in nostr 0.44; just call it.
    s.clone()
}

fn print_help() {
    println!("commands:");
    println!("  /create <npub> <npub>   — create group with two other members");
    println!("  /invite <npub>          — invite another member to current group");
    println!("  /send <text>            — send message to current group");
    println!("  /leave                  — self-remove from current group");
    println!("  /features               — show FeatureStatus for each registered feature");
    println!("  /members                — list group members");
    println!("  /status                 — show my identity");
    println!("  /help                   — show this");
    println!("  /quit                   — exit");
    println!();
    println!("env:  DM_NSEC=<nsec>   — reuse identity across restarts");
    println!("      DM_DROP_CAPS=selfremove  — negative test: advertise a KP without SelfRemove");
}

fn print_prompt() {
    print!("» ");
    let _ = std::io::stdout().flush();
}

async fn handle_command(
    line: &str,
    session: &Arc<Session>,
    current_group: &Arc<Mutex<Option<GroupId>>>,
) -> Result<()> {
    let mut parts = line.split_whitespace();
    let cmd = parts.next().unwrap_or("");
    match cmd {
        "/help" => print_help(),
        "/status" => {
            let npub = session.public_key().to_bech32().unwrap_or_else(|_| "?".into());
            println!("npub: {npub}");
            let g = current_group.lock().await.clone();
            match g {
                None => println!("current group: (none)"),
                Some(gid) => println!("current group: {}", gid.as_hex()),
            }
        }
        "/create" => {
            let args: Vec<_> = parts.collect();
            if args.len() != 2 {
                return Err(anyhow!("usage: /create <npub> <npub>"));
            }
            let m1 = parse_npub(args[0])?;
            let m2 = parse_npub(args[1])?;
            println!("[fetching key packages…]");
            let gid = session
                .create_group("spike", "darkmatter spike chat", vec![m1, m2])
                .await?;
            *current_group.lock().await = Some(gid.clone());
            println!("[created group {} — commit + welcomes published]", gid.as_hex());
        }
        "/invite" => {
            let args: Vec<_> = parts.collect();
            if args.len() != 1 {
                return Err(anyhow!("usage: /invite <npub>"));
            }
            let pk = parse_npub(args[0])?;
            let gid = current_group.lock().await.clone();
            let gid = gid.ok_or_else(|| anyhow!("no current group"))?;
            println!("[fetching key package + sending commit…]");
            session.invite(gid, pk).await?;
            println!("[invited]");
        }
        "/leave" => {
            let gid = current_group.lock().await.clone();
            let gid = gid.ok_or_else(|| anyhow!("no current group"))?;
            session.leave(gid.clone()).await?;
            *current_group.lock().await = None;
            println!("[left group]");
        }
        "/features" => {
            let gid = current_group.lock().await.clone();
            let gid = gid.ok_or_else(|| anyhow!("no current group"))?;
            let statuses = session.feature_statuses(&gid).await?;
            println!("features in group {}:", gid.as_hex());
            for (f, st) in statuses {
                let label = match st {
                    FeatureStatus::Available => "AVAILABLE",
                    FeatureStatus::Upgradeable => "upgradeable",
                    FeatureStatus::Unavailable { .. } => "unavailable",
                };
                println!("  {:<24} → {}", format!("{:?}", f), label);
            }
        }
        "/send" => {
            let text = line
                .strip_prefix("/send")
                .unwrap_or("")
                .trim()
                .to_string();
            if text.is_empty() {
                return Err(anyhow!("usage: /send <text>"));
            }
            let gid = current_group.lock().await.clone();
            let gid = gid.ok_or_else(|| anyhow!("no current group — run /create or wait for welcome"))?;
            session.send_message(gid, &text).await?;
            println!("[sent]");
        }
        "/members" => {
            let gid = current_group.lock().await.clone();
            let _gid = gid.ok_or_else(|| anyhow!("no current group"))?;
            println!("(members query not wired in spike)");
        }
        "/quit" | "/exit" => {
            std::process::exit(0);
        }
        other => {
            return Err(anyhow!("unknown command: {other}"));
        }
    }
    Ok(())
}

async fn print_event(
    ev: &GroupEvent,
    current_group: &Arc<Mutex<Option<GroupId>>>,
    my_pk_bytes: [u8; 32],
) {
    match ev {
        GroupEvent::GroupCreated { group_id, epoch } => {
            println!();
            println!("[GroupCreated: {} epoch={}]", group_id.as_hex(), epoch.0);
        }
        GroupEvent::Joined { group_id, epoch } => {
            println!();
            println!("[Joined: {} epoch={}]", group_id.as_hex(), epoch.0);
            *current_group.lock().await = Some(group_id.clone());
        }
        GroupEvent::ApplicationMessage {
            sender,
            rumor_bytes,
            epoch,
            ..
        } => {
            let is_me = sender.0 == my_pk_bytes;
            let sender_label = if is_me {
                "me".to_string()
            } else {
                format!("{}…", &sender.as_hex()[..8])
            };
            let text = extract_rumor_text(rumor_bytes).unwrap_or_else(|| "<binary>".into());
            println!();
            println!("[{sender_label} @ epoch {}] {text}", epoch.0);
        }
        GroupEvent::MemberAdded {
            member, epoch, ..
        } => {
            println!();
            println!("[+ member {} epoch={}]", hex_prefix(&member.0), epoch.0);
        }
        GroupEvent::MemberRemoved {
            member, epoch, ..
        } => {
            println!();
            println!("[- member {} epoch={}]", hex_prefix(&member.0), epoch.0);
        }
        GroupEvent::EpochAdvanced { new_epoch, .. } => {
            println!();
            println!("[epoch → {}]", new_epoch.0);
        }
    }
}

fn hex_prefix(bytes: &[u8; 32]) -> String {
    let mut s = hex::encode(bytes);
    s.truncate(8);
    s
}

fn extract_rumor_text(bytes: &[u8]) -> Option<String> {
    let val: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    val.get("content")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}
