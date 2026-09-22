//! Deployment-global operator-listener mention matching and notification delivery.

use std::{sync::Arc, time::Duration};

use chrono::{TimeDelta, Utc};
use futures_util::future::join_all;
use serde::Serialize;
use tracing::{error, warn};

use crate::{nip98::nip98_header, state::AppState};

use reqwest::StatusCode;

const CLAIM_SECS: i64 = 30;
const DELIVERY_BATCH_LIMIT: i64 = 10;
const IDLE_POLL_FLOOR: Duration = Duration::from_millis(250);
const IDLE_POLL_CEILING: Duration = Duration::from_secs(2);
const REAP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Notification sent to the configured operator-listener endpoint.
#[derive(Debug, Serialize)]
struct MentionNotification {
    v: u8,
    pubkey: String,
    community_host: String,
    event_id: String,
    event_kind: i32,
    event_created_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerIteration {
    Worked,
    Idle,
    Failed,
}

/// Reap stale deliveries and registrations. Registration cleanup is deliberately
/// daily and does not coordinate with registration requests.
pub async fn run_reaper(state: Arc<AppState>) {
    loop {
        if let Err(error) = state.db.delete_expired_operator_listener_pubkeys().await {
            warn!(%error, "operator-listener registration cleanup failed");
        }
        if let Err(error) = state.db.reap_operator_listener_deliveries().await {
            warn!(%error, "operator-listener outbox reap failed");
        }
        tokio::time::sleep(REAP_INTERVAL).await;
    }
}

/// Continuously deliver operator-listener notification rows with bounded concurrency and retries.
pub async fn run_delivery_worker(state: Arc<AppState>) {
    let http = match reqwest::Client::builder()
        .timeout(state.config.operator_listener_timeout)
        .build()
    {
        Ok(http) => http,
        Err(error) => {
            error!(%error, "operator-listener HTTP client initialization failed");
            return;
        }
    };
    let mut idle_delay = IDLE_POLL_FLOOR;
    loop {
        match run_delivery_once(&state, &http).await {
            WorkerIteration::Worked => idle_delay = IDLE_POLL_FLOOR,
            WorkerIteration::Idle => {
                tokio::time::sleep(idle_delay).await;
                idle_delay = (idle_delay * 2).min(IDLE_POLL_CEILING);
            }
            WorkerIteration::Failed => tokio::time::sleep(Duration::from_secs(2)).await,
        }
    }
}

async fn run_delivery_once(state: &AppState, http: &reqwest::Client) -> WorkerIteration {
    let transport = ReqwestDeliveryTransport { http };
    run_delivery_once_with_transport(state, &transport).await
}

#[async_trait::async_trait]
trait DeliveryTransport: Sync {
    async fn post(
        &self,
        url: &url::Url,
        authorization: &str,
        body: Vec<u8>,
    ) -> Result<StatusCode, String>;
}

struct ReqwestDeliveryTransport<'a> {
    http: &'a reqwest::Client,
}

#[async_trait::async_trait]
impl DeliveryTransport for ReqwestDeliveryTransport<'_> {
    async fn post(
        &self,
        url: &url::Url,
        authorization: &str,
        body: Vec<u8>,
    ) -> Result<StatusCode, String> {
        self.http
            .post(url.clone())
            .header("Authorization", authorization)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map(|response| response.status())
            .map_err(|error| error.to_string())
    }
}

async fn run_delivery_once_with_transport<T: DeliveryTransport>(
    state: &AppState,
    transport: &T,
) -> WorkerIteration {
    let claimed = match state
        .db
        .claim_operator_listener_deliveries(
            DELIVERY_BATCH_LIMIT,
            Utc::now() + TimeDelta::seconds(CLAIM_SECS),
        )
        .await
    {
        Ok(claimed) => claimed,
        Err(error) => {
            error!(%error, "operator-listener delivery claim failed");
            return WorkerIteration::Failed;
        }
    };
    if claimed.is_empty() {
        return WorkerIteration::Idle;
    }
    join_all(
        claimed
            .into_iter()
            .map(|delivery| deliver_one(state, transport, delivery)),
    )
    .await;
    WorkerIteration::Worked
}

async fn deliver_one<T: DeliveryTransport>(
    state: &AppState,
    transport: &T,
    delivery: buzz_db::operator_listener::ClaimedDelivery,
) {
    let listener_hex = hex::encode(&delivery.listener_pubkey);
    let Some(url) = state
        .config
        .operator_listener_delivery_urls
        .get(&listener_hex)
    else {
        warn!(
            delivery=%delivery.id,
            listener=%listener_hex,
            "operator-listener delivery has no route on this pod; releasing claim"
        );
        if let Err(error) = state
            .db
            .release_operator_listener_delivery(
                delivery.id,
                delivery.claim_id,
                Utc::now() + TimeDelta::seconds(CLAIM_SECS),
            )
            .await
        {
            error!(%error, delivery=%delivery.id, "failed to release unroutable operator-listener delivery");
        }
        metrics::counter!("buzz_operator_listener_deliveries_total", "outcome" => "unroutable")
            .increment(1);
        return;
    };
    let body = match serde_json::to_vec(&MentionNotification {
        v: 1,
        pubkey: hex::encode(&delivery.target_pubkey),
        community_host: delivery.community_host.clone(),
        event_id: hex::encode(&delivery.event_id),
        event_kind: delivery.event_kind,
        event_created_at: delivery.event_created_at.timestamp(),
    }) {
        Ok(body) => body,
        Err(error) => {
            fail_permanently(
                state,
                &delivery,
                &format!("notification encoding failed: {error}"),
            )
            .await;
            return;
        }
    };
    let auth = match nip98_header(&state.relay_keypair, url.as_str(), &body) {
        Ok(auth) => auth,
        Err(error) => {
            fail_permanently(
                state,
                &delivery,
                &format!("notification auth failed: {error}"),
            )
            .await;
            return;
        }
    };
    let response = transport.post(url, &auth, body).await;
    match response {
        Ok(status) if status.is_success() => {
            match state
                .db
                .complete_operator_listener_delivery(delivery.id, delivery.claim_id)
                .await
            {
                Ok(true) => {}
                Ok(false) => warn!(
                    delivery=%delivery.id,
                    "operator-listener delivery completion lost its claim"
                ),
                Err(error) => error!(
                    delivery=%delivery.id,
                    %error,
                    "failed to persist operator-listener delivery completion"
                ),
            }
            metrics::counter!("buzz_operator_listener_deliveries_total", "outcome" => "accepted")
                .increment(1);
        }
        Ok(status) => retry_or_fail(state, &delivery, format!("HTTP {status}")).await,
        Err(error) => retry_or_fail(state, &delivery, error.to_string()).await,
    }
}

async fn fail_permanently(
    state: &AppState,
    delivery: &buzz_db::operator_listener::ClaimedDelivery,
    reason: &str,
) {
    error!(delivery=%delivery.id, %reason, "operator-listener delivery failed permanently");
    if let Err(error) = state
        .db
        .fail_operator_listener_delivery(delivery.id, delivery.claim_id)
        .await
    {
        error!(delivery=%delivery.id, %error, "failed to delete terminal operator-listener delivery");
    }
    metrics::counter!("buzz_operator_listener_deliveries_total", "outcome" => "failed")
        .increment(1);
}

async fn retry_or_fail(
    state: &AppState,
    delivery: &buzz_db::operator_listener::ClaimedDelivery,
    reason: String,
) {
    if delivery.attempt >= buzz_db::operator_listener::MAX_DELIVERY_ATTEMPTS {
        fail_permanently(state, delivery, &format!("retries exhausted: {reason}")).await;
        return;
    }
    let delay = 2_i64.pow((delivery.attempt - 1).clamp(0, 7) as u32);
    warn!(
        delivery=%delivery.id,
        attempt=delivery.attempt,
        retry_in_seconds=delay,
        %reason,
        "operator-listener delivery failed; retrying"
    );
    if let Err(error) = state
        .db
        .retry_operator_listener_delivery(
            delivery.id,
            delivery.claim_id,
            Utc::now() + TimeDelta::seconds(delay),
        )
        .await
    {
        error!(delivery=%delivery.id, %error, "failed to persist operator-listener retry");
    }
    metrics::counter!("buzz_operator_listener_deliveries_total", "outcome" => "retry").increment(1);
}
