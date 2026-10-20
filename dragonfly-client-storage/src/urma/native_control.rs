//! Owner-thread SEND/RECV endpoint. Its queues and LOCAL_ONLY buffers are
//! independent of READ credits. No native handle crosses the Fabric thread.
use super::{
    ffi::{
        self, read::ReadBufferCreation, CompletionEventKind, CompletionRecord, FfiError,
        JettyHandle, JfcHandle, NativeRuntime, SegmentHandle, TargetHandle, WrHandle,
    },
    lane::{JettyDescriptor, TpType},
    native_error, Error, Result,
};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT_CONTROL: AtomicU64 = AtomicU64::new(1);
use tokio::sync::{mpsc, oneshot};

pub(crate) const PACKET_BYTES: usize = 4096;
const RX_SLOTS: usize = 32;
pub(crate) const ENDPOINT_BYTES: u64 = ((RX_SLOTS + 1) * PACKET_BYTES) as u64;
type Reply = oneshot::Sender<Result<()>>;

pub(crate) struct ControlSetup {
    pub(crate) id: u64,
    pub(crate) descriptor: Vec<u8>,
    pub(crate) incoming: mpsc::Receiver<Result<Vec<u8>>>,
}

pub(crate) struct ControlProgress {
    pub(crate) closed: bool,
    /// Consumed CQ records, including flush/error events. The owner must not
    /// sleep as though the control queues were idle after making progress.
    pub(crate) events: usize,
}
struct Flight {
    wr: WrHandle,
    slot: usize,
    reply: Option<Reply>,
}

pub(crate) struct NativeControl {
    pub(crate) id: u64,
    send_cq: Option<JfcHandle>,
    recv_cq: Option<JfcHandle>,
    jetty: Option<JettyHandle>,
    target: Option<TargetHandle>,
    buffer: Option<SegmentHandle>,
    incoming: Option<mpsc::Sender<Result<Vec<u8>>>>,
    posted: HashMap<u64, Flight>,
    pending: VecDeque<(usize, Vec<u8>)>,
    next_context: u64,
    closing: bool,
    uncertain_buffer: bool,
    last_error: Option<String>,
    destroy_attempted: bool,
}
impl NativeControl {
    pub(crate) fn new() -> Result<(Self, mpsc::Receiver<Result<Vec<u8>>>)> {
        let id = NEXT_CONTROL
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| protocol("control identity exhausted"))?;
        let (tx, rx) = mpsc::channel(RX_SLOTS);
        Ok((
            Self {
                id,
                send_cq: None,
                recv_cq: None,
                jetty: None,
                target: None,
                buffer: None,
                incoming: Some(tx),
                posted: HashMap::new(),
                pending: VecDeque::new(),
                next_context: 1,
                closing: false,
                uncertain_buffer: false,
                last_error: None,
                destroy_attempted: false,
            },
            rx,
        ))
    }
    pub(crate) fn open(&mut self, runtime: &mut NativeRuntime, tp: TpType) -> Result<Vec<u8>> {
        self.send_cq = Some(JfcHandle::create(runtime, 16).map_err(err)?);
        self.recv_cq = Some(JfcHandle::create(runtime, 64).map_err(err)?);
        self.jetty = Some(
            JettyHandle::create(
                runtime,
                self.send_cq.as_ref().unwrap(),
                self.recv_cq.as_ref().unwrap(),
                &ffi::JettyConfig {
                    send_depth: 8,
                    recv_depth: RX_SLOTS as u32,
                    max_send_sge: 1,
                    max_recv_sge: 1,
                    token: 0,
                    tp_type: tp as u32,
                },
            )
            .map_err(err)?,
        );
        match SegmentHandle::create_read_buffer(runtime, ENDPOINT_BYTES, 4096) {
            ReadBufferCreation::Ready(buffer) => self.buffer = Some(buffer),
            ReadBufferCreation::Rejected(e) => return Err(err(e)),
            ReadBufferCreation::Uncertain { buffer, error } => {
                self.buffer = Some(buffer);
                self.uncertain_buffer = true;
                return Err(err(error));
            }
        }
        for slot in 0..RX_SLOTS {
            self.post(slot, None, PACKET_BYTES as u32)?;
        }
        JettyDescriptor::from_ffi(
            self.jetty
                .as_ref()
                .unwrap()
                .export_descriptor()
                .map_err(err)?,
        )?
        .serialize()
    }
    pub(crate) fn connect(&mut self, remote: &[u8], tp: TpType) -> Result<()> {
        if self.closing || self.target.is_some() {
            return Err(protocol("control endpoint not connectable"));
        }
        let descriptor = JettyDescriptor::deserialize(remote)?;
        if descriptor.tp_type != tp {
            return Err(protocol("control TP mismatch"));
        }
        self.target = Some(
            self.jetty
                .as_mut()
                .ok_or_else(|| protocol("control endpoint missing"))?
                .import_target(&descriptor.to_ffi()?, 0)
                .map_err(err)?,
        );
        Ok(())
    }
    fn post(&mut self, slot: usize, reply: Option<Reply>, length: u32) -> Result<()> {
        let context = self.next_context;
        self.next_context = context
            .checked_add(1)
            .ok_or_else(|| protocol("control context exhausted"))?;
        let (result, wr) = ffi::post_control(
            self.jetty.as_ref().unwrap(),
            if slot == RX_SLOTS {
                self.target.as_ref()
            } else {
                None
            },
            self.buffer.as_ref().unwrap(),
            (slot * PACKET_BYTES) as u64,
            length,
            context,
        );
        if let Some(wr) = wr {
            self.posted.insert(context, Flight { wr, slot, reply });
        } else if let Some(reply) = reply {
            let _ = reply.send(Err(protocol("control post was not accepted")));
        }
        result.map_err(err)
    }
    pub(crate) fn send(&mut self, data: Vec<u8>, reply: Reply) {
        let result = (|| {
            if self.closing
                || self.target.is_none()
                || data.is_empty()
                || data.len() > PACKET_BYTES
                || self.posted.values().any(|f| f.slot == RX_SLOTS)
            {
                return Err(protocol("control SEND unavailable or oversize"));
            }
            let (ptr, _) = self.buffer.as_ref().unwrap().data().map_err(err)?;
            // SAFETY: the dedicated TX slot has no outstanding WR; no other
            // CPU thread accesses it. The owner retains it until SEND CQE.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    ptr.as_ptr().add(RX_SLOTS * PACKET_BYTES),
                    data.len(),
                );
            }
            Ok(())
        })();
        if let Err(error) = result {
            let _ = reply.send(Err(error));
            return;
        }
        if let Err(error) = self.post(RX_SLOTS, Some(reply), data.len() as u32) {
            self.fail(error);
        }
    }
    pub(crate) fn stop(&mut self) {
        self.closing = true;
        self.incoming.take();
        self.pending.clear();
        for flight in self.posted.values_mut() {
            if let Some(reply) = flight.reply.take() {
                let _ = reply.send(Err(Error::Shutdown {
                    failures: vec!["control lane closed".into()],
                }));
            }
        }
        if let Some(jetty) = self.jetty.as_mut().filter(|_| !self.destroy_attempted) {
            if let Err(error) = jetty.mark_error() {
                self.last_error = Some(format!("mark_error: {error:?}"));
            }
        }
    }
    fn fail(&mut self, error: Error) {
        self.last_error = Some(error.to_string());
        if !self.closing {
            tracing::debug!(control_id = self.id, %error, "URMA SEND/RECV control endpoint failed");
            if let Some(tx) = self.incoming.take() {
                let _ = tx.try_send(Err(error.clone()));
            }
            for flight in self.posted.values_mut() {
                if let Some(reply) = flight.reply.take() {
                    let _ = reply.send(Err(error.clone()));
                }
            }
        }
        self.stop();
    }
    pub(crate) fn retirement_diagnostic(&self) -> String {
        let rx = self.posted.values().filter(|f| f.slot != RX_SLOTS).count();
        format!(
            "control_id={} closing={} rx_wrs={} tx_wrs={} uncertain_buffer={} last_error={:?}",
            self.id,
            self.closing,
            rx,
            self.posted.len() - rx,
            self.uncertain_buffer,
            self.last_error,
        )
    }
    fn deliver(&mut self, slot: usize, bytes: Vec<u8>) -> Result<()> {
        let Some(tx) = &self.incoming else {
            return Ok(());
        };
        match tx.try_send(Ok(bytes)) {
            Ok(()) => self.post(slot, None, PACKET_BYTES as u32),
            Err(mpsc::error::TrySendError::Full(Ok(bytes))) => {
                self.pending.push_back((slot, bytes));
                Ok(())
            }
            _ => Err(protocol("control receiver closed")),
        }
    }
    fn complete(&mut self, cqe: CompletionRecord, receive: bool) -> Result<()> {
        let (jetty_id, jfr_id) = self
            .jetty
            .as_ref()
            .ok_or_else(|| protocol("control jetty missing"))?
            .local_ids()
            .map_err(err)?;
        if cqe.local_id != if cqe.is_jetty { jetty_id } else { jfr_id } {
            return Err(protocol("control CQE endpoint mismatch"));
        }
        if cqe.event_kind == CompletionEventKind::FlushErrorDone && self.closing {
            let ids: Vec<_> = self
                .posted
                .iter()
                .filter(|(_, f)| (f.slot != RX_SLOTS) == receive)
                .map(|(&id, _)| id)
                .collect();
            for id in ids {
                self.posted.remove(&id).unwrap().wr.complete();
            }
            return Ok(());
        }
        validate_work_completion(&cqe, receive)?;
        let Some(flight) = self.posted.get(&cqe.user_ctx) else {
            return Err(protocol("unknown control CQE context"));
        };
        let (jetty_id, jfr_id) = self.jetty.as_ref().unwrap().local_ids().map_err(err)?;
        if (flight.slot != RX_SLOTS) != receive
            || cqe.is_recv != receive
            || cqe.local_id != if cqe.is_jetty { jetty_id } else { jfr_id }
        {
            return Err(protocol("control CQE queue/endpoint mismatch"));
        }
        let flight = self.posted.remove(&cqe.user_ctx).unwrap();
        flight.wr.complete();
        if cqe.status != 0 {
            if let Some(reply) = flight.reply {
                let _ = reply.send(Err(protocol("control SEND CQE failed")));
            }
            return Err(protocol(format!("control CQE status {}", cqe.status)));
        }
        if self.closing {
            return Ok(());
        }
        if receive {
            let length = cqe.completion_len as usize;
            if length == 0 || length > PACKET_BYTES {
                return Err(protocol("control receive length invalid"));
            }
            let (ptr, _) = self.buffer.as_ref().unwrap().data().map_err(err)?;
            // SAFETY: RECV CQE retired this slot, not reposted until copying.
            let bytes = unsafe {
                std::slice::from_raw_parts(ptr.as_ptr().add(flight.slot * PACKET_BYTES), length)
            }
            .to_vec();
            self.deliver(flight.slot, bytes)?;
        } else if let Some(reply) = flight.reply {
            let _ = reply.send(Ok(()));
        }
        Ok(())
    }
    /// Native CQ progress and cleanup stay on the same owner as READ. A
    /// non-closed endpoint retains ownership, including uncertain registration.
    pub(crate) fn progress(&mut self) -> ControlProgress {
        // A failed provider destroy may have partially dismantled the endpoint.
        // Retain everything and do not poll/retry through uncertain handles.
        if self.destroy_attempted {
            return ControlProgress {
                closed: false,
                events: 0,
            };
        }
        let mut events = 0;
        let result = (|| {
            if self.incoming.as_ref().is_some_and(|tx| tx.is_closed()) {
                self.stop();
            }
            let mut completions = [CompletionRecord::default(); 16];
            for receive in [false, true] {
                let cq = if receive {
                    &self.recv_cq
                } else {
                    &self.send_cq
                };
                let count = match cq {
                    Some(cq) => cq.poll_into(&mut completions).map_err(err)?,
                    None => 0,
                };
                events += count;
                for cqe in completions.iter().take(count) {
                    if let Err(error) = self.complete(*cqe, receive) {
                        self.fail(error);
                    }
                }
            }
            if !self.closing {
                let count = self.pending.len();
                for _ in 0..count {
                    if self.incoming.as_ref().is_some_and(|tx| tx.capacity() == 0) {
                        break;
                    }
                    let (slot, bytes) = self.pending.pop_front().unwrap();
                    self.deliver(slot, bytes)?;
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.fail(error);
        }
        if self.closing
            && !self.uncertain_buffer
            && !self.posted.is_empty()
            && self.posted.values().all(|f| f.slot != RX_SLOTS)
        {
            let result = (|| {
                if let Some(target) = &mut self.target {
                    target.close().map_err(err)?;
                }
                self.destroy_attempted = true;
                self.jetty
                    .as_mut()
                    .ok_or_else(|| protocol("control endpoint missing"))?
                    .destroy_control_recv_endpoint()
                    .map_err(err)?;
                // Synchronous native destruction is the retirement proof for
                // these unused receives. The WR arena and buffer stayed alive.
                for (_, flight) in self.posted.drain() {
                    flight.wr.complete();
                }
                Ok::<_, Error>(())
            })();
            if let Err(error) = result {
                self.last_error = Some(format!("destroy stopped RECV endpoint: {error}"));
            }
        }
        if !self.closing || !self.posted.is_empty() || self.uncertain_buffer {
            return ControlProgress {
                closed: false,
                events,
            };
        }
        let result = (|| {
            if let Some(target) = &mut self.target {
                target
                    .close()
                    .map_err(|e| protocol(format!("control unimport target: {e:?}")))?;
            }
            if let Some(jetty) = &mut self.jetty {
                jetty
                    .close()
                    .map_err(|e| protocol(format!("control close jetty/JFR: {e:?}")))?;
            }
            if let Some(buffer) = &mut self.buffer {
                buffer
                    .close()
                    .map_err(|e| protocol(format!("control close buffer: {e:?}")))?;
            }
            if let Some(cq) = &mut self.recv_cq {
                cq.close()
                    .map_err(|e| protocol(format!("control close recv CQ: {e:?}")))?;
            }
            if let Some(cq) = &mut self.send_cq {
                cq.close()
                    .map_err(|e| protocol(format!("control close send CQ: {e:?}")))?;
            }
            Ok::<_, Error>(())
        })();
        if let Err(error) = &result {
            self.last_error = Some(error.to_string());
        }
        ControlProgress {
            closed: result.is_ok(),
            events,
        }
    }
}
fn protocol(message: impl Into<String>) -> Error {
    Error::Protocol(message.into())
}
fn err(error: FfiError) -> Error {
    native_error("control SEND/RECV", error)
}

fn validate_work_completion(cqe: &CompletionRecord, receive: bool) -> Result<()> {
    // URMA_OPC_SEND describes a submitted WR, not its completion. Receive
    // completions use urma_cr_opcode_t (URMA_CR_OPC_SEND); udma's send-CQ
    // parser does not populate opcode. SEND identity comes from the posted
    // context and queue/endpoint checks in complete(), as for READ CQEs.
    if cqe.event_kind != CompletionEventKind::WorkRequest
        || !cqe.user_ctx_valid
        || cqe.is_recv != receive
        || (receive && cqe.status == 0 && cqe.opcode != ffi::CONTROL_RECV_OPCODE)
    {
        return Err(protocol(format!(
            "unroutable control CQE: status={} opcode={} receive={} expected_receive={} context_valid={} event={:?}",
            cqe.status, cqe.opcode, cqe.is_recv, receive, cqe.user_ctx_valid, cqe.event_kind,
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retirement_diagnostic_retains_errors_after_stop() {
        let (mut control, _rx) = NativeControl::new().unwrap();
        control.fail(protocol("fixture flush error"));
        let diagnostic = control.retirement_diagnostic();
        assert!(diagnostic.contains("closing=true rx_wrs=0 tx_wrs=0"));
        assert!(diagnostic.contains("fixture flush error"));
        control.stop();
        assert_eq!(diagnostic, control.retirement_diagnostic());
    }

    #[test]
    fn udma_send_and_recv_completions_do_not_use_the_wr_send_opcode() {
        // udma fills receive opcode with URMA_CR_OPC_SEND (0), and leaves
        // send opcode unset (the shim zero-initializes its polling buffer).
        let mut cqe = CompletionRecord {
            user_ctx: 17,
            user_ctx_valid: true,
            opcode: 0,
            ..Default::default()
        };
        validate_work_completion(&cqe, false).unwrap();
        cqe.is_recv = true;
        cqe.completion_len = 128;
        validate_work_completion(&cqe, true).unwrap();
        cqe.opcode = 0x40; // URMA_OPC_SEND belongs to WRs, not receive CQEs.
        assert!(validate_work_completion(&cqe, true).is_err());
        cqe.is_recv = false;
        cqe.opcode = u32::MAX; // Send opcode is not a provider guarantee.
        validate_work_completion(&cqe, false).unwrap();
    }

    #[test]
    fn control_completion_still_requires_valid_context_and_correct_queue() {
        let mut cqe = CompletionRecord {
            user_ctx_valid: true,
            ..Default::default()
        };
        assert!(validate_work_completion(&cqe, true).is_err());
        cqe.user_ctx_valid = false;
        assert!(validate_work_completion(&cqe, false).is_err());
        cqe.user_ctx_valid = true;
        cqe.event_kind = CompletionEventKind::FlushErrorDone;
        assert!(validate_work_completion(&cqe, false).is_err());
        cqe.event_kind = CompletionEventKind::SuspendDone;
        assert!(validate_work_completion(&cqe, false).is_err());
        cqe.event_kind = CompletionEventKind::WorkRequest;
        cqe.is_recv = true;
        cqe.status = 1; // Failed WRs need not carry a successful opcode.
        cqe.opcode = u32::MAX;
        validate_work_completion(&cqe, true).unwrap();
    }
}
