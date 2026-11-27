use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use h3::{
    error::Code,
    quic::{self, ConnectionErrorIncoming, OpenStreams, StreamErrorIncoming},
};

// h3 checks decoded field sizes after collecting each non-DATA frame. Apply a
// limit to those frames before their bytes enter the h3 decoder.
pub struct Limited<T> {
    inner: T,
    max_frame: u64,
}

impl<T> Limited<T> {
    pub fn new(inner: T, max_frame: usize) -> Self {
        Self {
            inner,
            max_frame: max_frame as u64,
        }
    }
}

impl<T> OpenStreams<Bytes> for Limited<T>
where
    T: OpenStreams<
            Bytes,
            BidiStream = h3_quinn::BidiStream<Bytes>,
            SendStream = h3_quinn::SendStream<Bytes>,
        >,
{
    type BidiStream = Checked<h3_quinn::BidiStream<Bytes>>;
    type SendStream = h3_quinn::SendStream<Bytes>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        self.inner
            .poll_open_bidi(cx)
            .map_ok(|inner| Checked::new(inner, FrameBudget::request(self.max_frame)))
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        self.inner.poll_open_send(cx)
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        self.inner.close(code, reason);
    }
}

impl quic::Connection<Bytes> for Limited<h3_quinn::Connection> {
    type RecvStream = Checked<h3_quinn::RecvStream>;
    type OpenStreams = Limited<h3_quinn::OpenStreams>;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        <h3_quinn::Connection as quic::Connection<Bytes>>::poll_accept_recv(&mut self.inner, cx)
            .map_ok(|inner| Checked::new(inner, FrameBudget::unidirectional(self.max_frame)))
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        self.inner
            .poll_accept_bidi(cx)
            .map_ok(|inner| Checked::new(inner, FrameBudget::request(self.max_frame)))
    }

    fn opener(&self) -> Self::OpenStreams {
        Limited {
            inner: <h3_quinn::Connection as quic::Connection<Bytes>>::opener(&self.inner),
            max_frame: self.max_frame,
        }
    }
}

pub struct Checked<T> {
    inner: T,
    budget: FrameBudget,
}

impl<T> Checked<T> {
    fn new(inner: T, budget: FrameBudget) -> Self {
        Self { inner, budget }
    }
}

impl<T: quic::RecvStream<Buf = Bytes>> quic::RecvStream for Checked<T> {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        let data = ready!(self.inner.poll_data(cx))?;
        if let Some(bytes) = &data
            && !self.budget.consume(bytes)
        {
            let error_code = Code::H3_EXCESSIVE_LOAD.value();
            self.inner.stop_sending(error_code);
            return Poll::Ready(Err(StreamErrorIncoming::StreamTerminated { error_code }));
        }
        Poll::Ready(Ok(data))
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.inner.stop_sending(error_code);
    }
    fn recv_id(&self) -> quic::StreamId {
        self.inner.recv_id()
    }
}

impl<T: quic::SendStream<Bytes>> quic::SendStream<Bytes> for Checked<T> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.inner.poll_ready(cx)
    }
    fn send_data<D: Into<quic::WriteBuf<Bytes>>>(
        &mut self,
        data: D,
    ) -> Result<(), StreamErrorIncoming> {
        self.inner.send_data(data)
    }
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.inner.poll_finish(cx)
    }
    fn reset(&mut self, code: u64) {
        self.inner.reset(code);
    }
    fn send_id(&self) -> quic::StreamId {
        self.inner.send_id()
    }
}

impl quic::BidiStream<Bytes> for Checked<h3_quinn::BidiStream<Bytes>> {
    type SendStream = h3_quinn::SendStream<Bytes>;
    type RecvStream = Checked<h3_quinn::RecvStream>;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        let (send, receive) = self.inner.split();
        (send, Checked::new(receive, self.budget))
    }
}

struct FrameBudget {
    phase: Phase,
    max_frame: u64,
    request: bool,
    varint: VarInt,
}

#[derive(Clone, Copy)]
enum Phase {
    StreamType,
    FrameType,
    FrameLength(u64),
    Payload(u64),
    Unframed,
}

impl FrameBudget {
    fn request(max_frame: u64) -> Self {
        Self {
            max_frame,
            request: true,
            phase: Phase::FrameType,
            varint: VarInt::default(),
        }
    }

    fn unidirectional(max_frame: u64) -> Self {
        Self {
            max_frame,
            request: false,
            phase: Phase::StreamType,
            varint: VarInt::default(),
        }
    }

    fn consume(&mut self, mut bytes: &[u8]) -> bool {
        while bytes.has_remaining() {
            self.phase = match self.phase {
                Phase::Unframed => return true,
                Phase::Payload(left) => {
                    let eaten = left.min(bytes.remaining() as u64);
                    bytes.advance(eaten as usize);
                    if eaten == left {
                        Phase::FrameType
                    } else {
                        Phase::Payload(left - eaten)
                    }
                }
                phase => {
                    let Some(value) = self.varint.take(&mut bytes) else {
                        return true;
                    };
                    match phase {
                        Phase::StreamType if value == 0 => Phase::FrameType,
                        Phase::StreamType => Phase::Unframed,
                        Phase::FrameType => Phase::FrameLength(value),
                        Phase::FrameLength(kind) => {
                            if value > self.max_frame && !(self.request && kind == 0) {
                                return false;
                            }
                            if value == 0 {
                                Phase::FrameType
                            } else {
                                Phase::Payload(value)
                            }
                        }
                        _ => unreachable!(),
                    }
                }
            };
        }
        true
    }
}

#[derive(Default)]
struct VarInt {
    value: u64,
    remaining: u8,
}

impl VarInt {
    fn take(&mut self, bytes: &mut &[u8]) -> Option<u64> {
        if self.remaining == 0 {
            let first = bytes.get_u8();
            self.value = u64::from(first & 0x3f);
            self.remaining = (1 << (first >> 6)) - 1;
        }
        while self.remaining > 0 && bytes.has_remaining() {
            self.value = (self.value << 8) | u64::from(bytes.get_u8());
            self.remaining -= 1;
        }
        (self.remaining == 0).then_some(self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_budget_handles_fragmentation_and_streamed_data() {
        let mut check = FrameBudget::request(16);
        assert!(check.consume(&[0, 0x40]));
        assert!(check.consume(&[0x44, 0, 0]));
        assert!(check.consume(&[0; 66]));
        assert!(check.consume(&[1]));
        assert!(!check.consume(&[17]));
    }

    #[test]
    fn a_unidirectional_control_stream_also_bounds_frames() {
        assert!(!FrameBudget::unidirectional(16).consume(&[0, 4, 17]));
        assert!(FrameBudget::unidirectional(16).consume(&[2, 4, 17]));
    }
}
