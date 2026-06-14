//! `messages` command namespace handlers (incl. the `timeline` subgroup) and message output helpers.

use std::collections::HashMap;

use cgka_traits::GroupId;
use marmot_account::AccountHome;
use marmot_app::{
    AppMessageQuery, AppMessageRecord, MarmotApp, MarmotAppRuntime, TimelineMessageQuery,
    TimelineMessageRecord, TimelinePage, TimelinePagination,
};
use serde_json::{Value, json};

use crate::{
    CommandOutput, DmError, MessageCommand, MessageTimelineCommand,
    agent_text_stream_payload_value, display_name_for_sender, ensure_local_signing,
    normalize_group_id_hex, npub_for_account_id, resolve_account,
};

fn message_target_and_text(
    group_flag: Option<String>,
    mut args: Vec<String>,
) -> Result<(String, Vec<String>), DmError> {
    if let Some(group) = group_flag {
        return Ok((group, args));
    }
    if args.is_empty() {
        return Err(DmError::MissingGroupId);
    }
    let group = args.remove(0);
    Ok((group, args))
}

pub(crate) async fn message_command(
    account_home: &AccountHome,
    app: &MarmotApp,
    command: MessageCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    let runtime = app.runtime();
    message_command_with_runtime(account_home, app, &runtime, command, account_flag).await
}

pub(crate) async fn message_command_with_runtime(
    account_home: &AccountHome,
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    command: MessageCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        MessageCommand::Send { group_flag, args } => {
            let (group, text) = message_target_and_text(group_flag, args)?;
            if text.is_empty() {
                return Err(DmError::EmptyMessage);
            }
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id_hex = normalize_group_id_hex(&group)?;
            let group_id = GroupId::new(hex::decode(&group_id_hex)?);
            let payload = text.join(" ");
            let summary = runtime
                .send_message(&account.label, &group_id, payload.into_bytes())
                .await?;
            Ok(CommandOutput {
                plain: format!("sent message published={}", summary.published),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": hex::encode(group_id.as_slice()),
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        MessageCommand::Delete {
            group_id,
            message_id,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group_id)?)?);
            let summary = runtime
                .delete_message(&account.label, &group_id, &message_id)
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "deleted message {message_id} published={}",
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": hex::encode(group_id.as_slice()),
                    "target_message_id": message_id,
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        MessageCommand::Retry { group_id, event_id } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group_id)?)?);
            let summary = runtime
                .retry_group_convergence(&account.label, &group_id)
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "retried group convergence for {event_id} published={}",
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": hex::encode(group_id.as_slice()),
                    "target_event_id": event_id,
                    "retry_scope": "group_convergence",
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        MessageCommand::React {
            group_id,
            message_id,
            emoji,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group_id)?)?);
            let summary = runtime
                .react_to_message(&account.label, &group_id, &message_id, &emoji)
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "reacted {emoji} to {message_id} published={}",
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": hex::encode(group_id.as_slice()),
                    "target_message_id": message_id,
                    "emoji": emoji,
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        MessageCommand::Unreact {
            group_id,
            message_id,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group_id = GroupId::new(hex::decode(normalize_group_id_hex(&group_id)?)?);
            let summary = runtime
                .unreact_from_message(&account.label, &group_id, &message_id)
                .await?;
            Ok(CommandOutput {
                plain: format!(
                    "removed reaction from {message_id} published={}",
                    summary.published
                ),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "group_id": hex::encode(group_id.as_slice()),
                    "target_message_id": message_id,
                    "published": summary.published,
                    "message_ids": summary.message_ids,
                }),
            })
        }
        MessageCommand::List {
            group_id,
            group,
            before,
            before_message_id,
            after,
            after_message_id,
            limit,
        } => {
            validate_message_list_cursors(
                before,
                before_message_id.as_deref(),
                after,
                after_message_id.as_deref(),
            )?;
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group = group.or(group_id);
            let uses_cursor = before.is_some()
                || before_message_id.is_some()
                || after.is_some()
                || after_message_id.is_some();
            let mut messages = app.messages_with_query(
                &account.label,
                AppMessageQuery {
                    group_id_hex: group
                        .map(|group| normalize_group_id_hex(&group))
                        .transpose()?,
                    limit: if uses_cursor { None } else { limit },
                },
            )?;
            if uses_cursor {
                messages = apply_message_cursors(
                    messages,
                    before,
                    before_message_id.as_deref(),
                    after,
                    after_message_id.as_deref(),
                    limit,
                );
            }
            Ok(CommandOutput {
                plain: message_list_plain(&messages),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "messages": message_list_json_with_profiles(app, messages),
                }),
            })
        }
        MessageCommand::Timeline { command } => {
            handle_message_timeline_command(app, account_home, command, account_flag)
        }
        MessageCommand::Search {
            group_id,
            query,
            limit,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let messages = search_messages(app, &account.label, Some(group_id), &query, limit)?;
            Ok(CommandOutput {
                plain: message_list_plain(&messages),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "query": query,
                    "messages": message_list_json_with_profiles(app, messages),
                }),
            })
        }
        MessageCommand::SearchAll { query, limit } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let messages = search_messages(app, &account.label, None, &query, limit)?;
            Ok(CommandOutput {
                plain: message_list_plain(&messages),
                json: json!({
                    "account_id": account.account_id_hex,
                    "npub": npub_for_account_id(&account.account_id_hex),
                    "query": query,
                    "messages": message_list_json_with_profiles(app, messages),
                }),
            })
        }
        MessageCommand::Subscribe { .. } => Err(DmError::MessagesSubscribeRequiresDaemon),
    }
}

fn handle_message_timeline_command(
    app: &MarmotApp,
    account_home: &AccountHome,
    command: MessageTimelineCommand,
    account_flag: Option<String>,
) -> Result<CommandOutput, DmError> {
    match command {
        MessageTimelineCommand::List {
            group_id,
            group,
            before,
            before_message_id,
            after,
            after_message_id,
            limit,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group = group.or(group_id);
            let page = app.timeline_messages_with_query(
                &account.label,
                TimelineMessageQuery {
                    group_id_hex: group
                        .map(|group| normalize_group_id_hex(&group))
                        .transpose()?,
                    search: None,
                    pagination: TimelinePagination {
                        before,
                        before_message_id,
                        before_inclusive: false,
                        after,
                        after_message_id,
                        limit,
                    },
                },
            )?;
            Ok(timeline_page_output(
                app,
                &account.account_id_hex,
                page,
                None,
            ))
        }
        MessageTimelineCommand::Search {
            query,
            group_id,
            group,
            limit,
        } => {
            let account = resolve_account(account_home, account_flag)?;
            ensure_local_signing(&account)?;
            app.status(&account.label)?;
            let group = group.or(group_id);
            let page = app.timeline_messages_with_query(
                &account.label,
                TimelineMessageQuery {
                    group_id_hex: group
                        .map(|group| normalize_group_id_hex(&group))
                        .transpose()?,
                    search: Some(query.clone()),
                    pagination: TimelinePagination {
                        limit,
                        ..TimelinePagination::default()
                    },
                },
            )?;
            Ok(timeline_page_output(
                app,
                &account.account_id_hex,
                page,
                Some(query),
            ))
        }
        MessageTimelineCommand::Subscribe { .. } => Err(DmError::MessagesSubscribeRequiresDaemon),
    }
}

fn search_messages(
    app: &MarmotApp,
    label: &str,
    group_id: Option<String>,
    query: &str,
    limit: Option<usize>,
) -> Result<Vec<AppMessageRecord>, DmError> {
    let group_id_hex = group_id
        .map(|group| normalize_group_id_hex(&group))
        .transpose()?;
    let mut matches = app
        .messages_with_query(
            label,
            AppMessageQuery {
                group_id_hex,
                limit: None,
            },
        )?
        .into_iter()
        .filter(|message| message.plaintext.contains(query))
        .collect::<Vec<_>>();
    if let Some(limit) = limit {
        matches.truncate(limit);
    }
    Ok(matches)
}

pub(crate) fn validate_message_list_cursors(
    before: Option<u64>,
    before_message_id: Option<&str>,
    after: Option<u64>,
    after_message_id: Option<&str>,
) -> Result<(), DmError> {
    if before.is_some() != before_message_id.is_some() {
        return Err(DmError::MessagePaginationCursorMismatch {
            timestamp_flag: "--before",
            message_id_flag: "--before-message-id",
        });
    }
    if after.is_some() != after_message_id.is_some() {
        return Err(DmError::MessagePaginationCursorMismatch {
            timestamp_flag: "--after",
            message_id_flag: "--after-message-id",
        });
    }
    if before.is_some() && after.is_some() {
        return Err(DmError::MessagePaginationConflictingCursors);
    }
    Ok(())
}

pub(crate) fn apply_message_cursors(
    mut messages: Vec<AppMessageRecord>,
    before: Option<u64>,
    before_message_id: Option<&str>,
    after: Option<u64>,
    after_message_id: Option<&str>,
    limit: Option<usize>,
) -> Vec<AppMessageRecord> {
    messages.retain(|message| {
        let before_matches = before.is_none_or(|cursor| {
            message.recorded_at < cursor
                || (message.recorded_at == cursor
                    && before_message_id
                        .is_some_and(|message_id| message.message_id_hex.as_str() < message_id))
        });
        let after_matches = after.is_none_or(|cursor| {
            message.recorded_at > cursor
                || (message.recorded_at == cursor
                    && after_message_id
                        .is_some_and(|message_id| message.message_id_hex.as_str() > message_id))
        });
        before_matches && after_matches
    });

    if let Some(limit) = limit
        && messages.len() > limit
    {
        if before.is_some() && after.is_none() {
            messages = messages.split_off(messages.len() - limit);
        } else {
            messages.truncate(limit);
        }
    }
    messages
}

fn message_list_plain(messages: &[AppMessageRecord]) -> String {
    if messages.is_empty() {
        return "no messages".to_owned();
    }
    messages
        .iter()
        .map(|message| {
            format!(
                "group={} from={}: {}",
                message.group_id_hex, message.sender, message.plaintext
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn message_list_json_with_profiles(app: &MarmotApp, messages: Vec<AppMessageRecord>) -> Vec<Value> {
    let mut display_names_by_sender: HashMap<String, Option<String>> = HashMap::new();
    messages
        .into_iter()
        .map(|message| {
            let from_display_name = display_names_by_sender
                .entry(message.sender.clone())
                .or_insert_with(|| display_name_for_sender(app, &message.sender))
                .clone();
            message_record_json(message, from_display_name)
        })
        .collect()
}

fn timeline_page_output(
    app: &MarmotApp,
    account_id_hex: &str,
    page: TimelinePage,
    query: Option<String>,
) -> CommandOutput {
    let plain = timeline_message_list_plain(&page.messages);
    let messages = timeline_message_list_json_with_profiles(app, page.messages);
    let mut json = json!({
        "account_id": account_id_hex,
        "npub": npub_for_account_id(account_id_hex),
        "messages": messages,
        "has_more_before": page.has_more_before,
        "has_more_after": page.has_more_after,
    });
    if let Some(query) = query {
        json["query"] = json!(query);
    }
    CommandOutput { plain, json }
}

fn timeline_message_list_plain(messages: &[TimelineMessageRecord]) -> String {
    if messages.is_empty() {
        return "no timeline messages".to_owned();
    }
    messages
        .iter()
        .map(|message| {
            let deleted = if message.deleted { " deleted=true" } else { "" };
            format!(
                "group={} from={}: {}{}",
                message.group_id_hex, message.sender, message.plaintext, deleted
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn timeline_message_list_json_with_profiles(
    app: &MarmotApp,
    messages: Vec<TimelineMessageRecord>,
) -> Vec<Value> {
    let mut display_names_by_sender: HashMap<String, Option<String>> = HashMap::new();
    messages
        .into_iter()
        .map(|message| {
            let from_display_name = display_names_by_sender
                .entry(message.sender.clone())
                .or_insert_with(|| display_name_for_sender(app, &message.sender))
                .clone();
            timeline_message_record_json(message, from_display_name)
        })
        .collect()
}

pub(crate) fn timeline_message_record_json(
    message: TimelineMessageRecord,
    from_display_name: Option<String>,
) -> Value {
    json!({
        "message_id": message.message_id_hex,
        "source_message_id": message.source_message_id_hex,
        "direction": message.direction,
        "group_id": message.group_id_hex,
        "from": message.sender,
        "from_display_name": from_display_name,
        "plaintext": message.plaintext,
        "kind": message.kind,
        "tags": message.tags,
        "timeline_at": message.timeline_at,
        "received_at": message.received_at,
        "reply_to_message_id": message.reply_to_message_id_hex,
        "reply_preview": message.reply_preview,
        "media": message.media,
        "agent_text_stream": message.agent_text_stream,
        "reactions": message.reactions,
        "deleted": message.deleted,
        "deleted_by_message_id": message.deleted_by_message_id_hex,
    })
}

pub(crate) fn message_record_json(
    message: AppMessageRecord,
    from_display_name: Option<String>,
) -> Value {
    let agent_text_stream =
        agent_text_stream_payload_value(message.kind, &message.tags, &message.plaintext);
    let mut value = json!({
        "message_id": message.message_id_hex,
        "direction": message.direction,
        "group_id": message.group_id_hex,
        "from": message.sender,
        "from_display_name": from_display_name,
        "plaintext": message.plaintext,
        "kind": message.kind,
        "tags": message.tags,
        "recorded_at": message.recorded_at,
        "received_at": message.received_at,
    });
    if let Some(agent_text_stream) = agent_text_stream {
        value["agent_text_stream"] = agent_text_stream;
    }
    value
}
