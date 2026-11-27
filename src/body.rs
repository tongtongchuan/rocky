use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::{BodyExt, Empty, Full, combinators::UnsyncBoxBody};
use tokio::time::{self, Sleep};

pub type BodyError = anyhow::Error;
pub type Body = UnsyncBoxBody<Bytes, BodyError>;

pub fn boxed<B>(body: B) -> Body
where
    B: HttpBody<Data = Bytes> + Send + 'static,
    B::Error: Into<BodyError>,
{
    body.map_err(Into::into).boxed_unsync()
}

pub fn empty() -> Body {
    boxed(Empty::new())
}

pub fn full(data: impl Into<Bytes>) -> Body {
    boxed(Full::new(data.into()))
}

pub fn constrain(body: Body, idle: Duration, limit: Option<(u64, Arc<AtomicBool>)>) -> Body {
    boxed(Constrained::new(body, idle, limit))
}

pub struct Constrained<B> {
    body: B,
    idle: Duration,
    timer: Option<Pin<Box<Sleep>>>,
    limit: Option<(u64, Arc<AtomicBool>)>,
    done: bool,
}

impl<B> Constrained<B> {
    pub fn new(body: B, idle: Duration, limit: Option<(u64, Arc<AtomicBool>)>) -> Self {
        Self {
            body,
            idle,
            timer: None,
            limit,
            done: false,
        }
    }
}

impl<B> HttpBody for Constrained<B>
where
    B: HttpBody<Data = Bytes> + Unpin,
    B::Error: Into<BodyError>,
{
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        if self.done {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.body).poll_frame(cx) {
            Poll::Ready(frame) => {
                self.timer = None;
                if let Some(Ok(frame)) = &frame
                    && let Some(data) = frame.data_ref()
                    && let Some((remaining, exceeded)) = &mut self.limit
                {
                    let Some(after) = remaining.checked_sub(data.len() as u64) else {
                        exceeded.store(true, Ordering::Release);
                        self.done = true;
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "request body limit exceeded",
                        )
                        .into())));
                    };
                    *remaining = after;
                }
                self.done = !matches!(frame, Some(Ok(_)));
                Poll::Ready(frame.map(|frame| frame.map_err(Into::into)))
            }
            Poll::Pending => {
                let idle = self.idle;
                let timer = self
                    .timer
                    .get_or_insert_with(|| Box::pin(time::sleep(idle)));
                if timer.as_mut().poll(cx).is_ready() {
                    self.done = true;
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "body idle deadline exceeded",
                    )
                    .into())));
                }
                Poll::Pending
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }

    fn is_end_stream(&self) -> bool {
        self.done || self.body.is_end_stream()
    }
}

pub struct Transfer {
    pub bytes: u64,
    pub outcome: &'static str,
}

pub fn observe(body: Body, finish: impl FnOnce(Transfer) + Send + 'static) -> Body {
    boxed(Observed {
        body,
        finish: Some(Box::new(finish)),
        bytes: 0,
    })
}

struct Observed {
    body: Body,
    finish: Option<Box<dyn FnOnce(Transfer) + Send>>,
    bytes: u64,
}

impl Observed {
    fn finish(&mut self, outcome: &'static str) {
        if let Some(finish) = self.finish.take() {
            finish(Transfer {
                bytes: self.bytes,
                outcome,
            });
        }
    }
}

impl Drop for Observed {
    fn drop(&mut self) {
        let outcome = if self.body.is_end_stream() {
            "complete"
        } else {
            "cancelled"
        };
        self.finish(outcome);
    }
}

impl HttpBody for Observed {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let frame = Pin::new(&mut self.body).poll_frame(cx);
        match &frame {
            Poll::Ready(Some(Ok(frame))) => {
                self.bytes += frame.data_ref().map_or(0, |data| data.len() as u64);
            }
            Poll::Ready(Some(Err(_))) => self.finish("body_error"),
            Poll::Ready(None) => self.finish("complete"),
            Poll::Pending => {}
        }
        frame
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
}
