use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::time::Duration;

use tokio::time::{Instant, timeout_at};

pub(crate) async fn collect_addresses<F, Query>(mut exchange: F) -> io::Result<Vec<IpAddr>>
where
    F: FnMut(usize, u16) -> Query,
    Query: Future<Output = io::Result<Vec<IpAddr>>>,
{
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut result = Vec::new();
    let mut exhausted = false;
    'servers: for server in 0..2 {
        for kind in [1, 28] {
            let now = Instant::now();
            if now >= deadline {
                exhausted = true;
                break 'servers;
            }
            let attempt_deadline = deadline.min(now + Duration::from_secs(2));
            if let Ok(Ok(addresses)) = timeout_at(attempt_deadline, exchange(server, kind)).await {
                for address in addresses.into_iter().take(8) {
                    if !result.contains(&address) {
                        result.push(address);
                    }
                }
            }
            if Instant::now() >= deadline {
                exhausted = true;
                break 'servers;
            }
        }
        if !result.is_empty() {
            break;
        }
    }
    if result.is_empty() {
        Err(if exhausted {
            io::ErrorKind::TimedOut
        } else {
            io::ErrorKind::NotFound
        }
        .into())
    } else {
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn regression_bootstrap_budget_preserves_success_at_four_point_one_seconds() {
        let started = Instant::now();
        let address: IpAddr = "1.1.1.1".parse().unwrap();
        let result = collect_addresses(|server, kind| async move {
            if server == 1 && kind == 1 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok(vec![address])
            } else {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Err(io::ErrorKind::TimedOut.into())
            }
        })
        .await
        .unwrap();
        assert_eq!(result, vec![address]);
        assert_eq!(started.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn regression_bootstrap_budget_never_waits_eight_seconds_for_four_silent_queries() {
        let started = Instant::now();
        let error = collect_addresses(|_, _| async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(Vec::new())
        })
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn regression_bootstrap_budget_keeps_immediate_failure_distinct_from_timeout() {
        let error =
            collect_addresses(|_, _| async { Err(io::ErrorKind::ConnectionRefused.into()) })
                .await
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}
