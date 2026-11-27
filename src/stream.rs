use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
    time::{self, Instant},
};

use crate::{
    listener::drain,
    runtime::{Metrics, StreamBinding, micros_since},
};

pub async fn relay(
    socket: TcpStream,
    rule: Arc<StreamBinding>,
    generation: u64,
    metrics: Arc<Metrics>,
) {
    let started = Instant::now();
    let sent = AtomicU64::new(0);
    let received = AtomicU64::new(0);
    let exchange = transfer(socket, &rule, &sent, &received);
    tokio::pin!(exchange);
    let outcome = tokio::select! {
        outcome = &mut exchange => outcome,
        deadline = rule.lifetime.retired() => drain(&metrics, deadline, &mut exchange).await.unwrap_or("drain_timeout"),
    };
    let sent = sent.load(Ordering::Relaxed);
    let received = received.load(Ordering::Relaxed);
    metrics.relays.fetch_add(1, Ordering::Relaxed);
    metrics
        .relay_upstream_bytes
        .fetch_add(sent, Ordering::Relaxed);
    metrics
        .relay_downstream_bytes
        .fetch_add(received, Ordering::Relaxed);
    tracing::info!(generation, listener = %rule.name, latency_us = micros_since(started), upstream_bytes = sent,
        downstream_bytes = received, outcome, "TCP relay");
}

async fn transfer(
    socket: TcpStream,
    rule: &StreamBinding,
    sent: &AtomicU64,
    received: &AtomicU64,
) -> &'static str {
    let upstream = match time::timeout(
        rule.settings.connect_timeout,
        TcpStream::connect(&*rule.settings.upstream),
    )
    .await
    {
        Ok(Ok(upstream)) => upstream,
        Ok(Err(_)) => return "connect_error",
        Err(_) => return "connect_timeout",
    };
    let _ = upstream.set_nodelay(true);
    let (client_read, client_write) = socket.into_split();
    let (server_read, server_write) = upstream.into_split();
    let (activity, observer) = watch::channel(Instant::now());
    let exchange = async {
        tokio::try_join!(
            copy(
                client_read,
                server_write,
                rule.buffer_bytes,
                sent,
                &activity
            ),
            copy(
                server_read,
                client_write,
                rule.buffer_bytes,
                received,
                &activity
            ),
        )
    };
    tokio::select! {
        result = exchange => if result.is_ok() { "complete" } else { "io_error" },
        _ = idle(observer, rule.settings.idle_timeout) => "idle_timeout",
    }
}

async fn idle(activity: watch::Receiver<Instant>, timeout: Duration) {
    loop {
        let deadline = *activity.borrow() + timeout;
        time::sleep_until(deadline).await;
        if Instant::now() >= *activity.borrow() + timeout {
            return;
        }
    }
}

async fn copy(
    mut read: impl AsyncRead + Unpin,
    mut write: impl AsyncWrite + Unpin,
    buffer_size: usize,
    bytes: &AtomicU64,
    activity: &watch::Sender<Instant>,
) -> io::Result<()> {
    let mut buffer = vec![0; buffer_size];
    loop {
        let amount = read.read(&mut buffer).await?;
        if amount == 0 {
            return write.shutdown().await;
        }
        activity.send_replace(Instant::now());
        let mut remaining = &buffer[..amount];
        while !remaining.is_empty() {
            let written = write.write(remaining).await?;
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "relay socket closed",
                ));
            }
            remaining = &remaining[written..];
            bytes.fetch_add(written as u64, Ordering::Relaxed);
            activity.send_replace(Instant::now());
        }
    }
}
