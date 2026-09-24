//! Handing the transport to the background pump while the target runs, and
//! taking it back when the target stops or the foreground needs the socket.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, mpsc};
use std::thread::spawn;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::kd::framing::BREAKIN_BYTE;

use super::{ContinueDrain, KdBackend, Link, PumpHandle, PumpLink, StateChange, run_pump};

impl KdBackend {
    /// Hand the framing to a freshly spawned background pump. The target has
    /// just been resumed (see [`record_running`]), so the link is inline.
    pub(super) fn start_pump(
        &mut self,
        reconnect_assist_delay: Option<Duration>,
        drain: Option<ContinueDrain>,
    ) -> Result<()> {
        let framing = match std::mem::replace(&mut self.link, Link::Lost) {
            Link::RunningInline(framing) => framing,
            other => {
                self.link = other;
                return Err(Error::Kd(
                    "cannot start KD pump: target is not resuming".into(),
                ));
            }
        };
        let (stop_tx, stop_rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let pump_shutdown = Arc::clone(&shutdown);
        let reported_stop = Arc::new(AtomicBool::new(false));
        let pump_reported_stop = Arc::clone(&reported_stop);
        let pump_debug_log = self.debug_log.clone();
        let arch = self.arch;
        let breakin_requested = drain
            .as_ref()
            .map(ContinueDrain::interrupt_flag)
            .unwrap_or_default();
        let join = spawn(move || {
            run_pump(
                framing,
                arch,
                PumpLink {
                    stop_tx,
                    shutdown: pump_shutdown,
                    reported_stop: pump_reported_stop,
                },
                reconnect_assist_delay,
                pump_debug_log,
                drain,
            )
        });
        kd_trace!("kd: pump: spawned background servicing thread");
        self.link.run_pumped(
            PumpHandle {
                join,
                stop_rx,
                shutdown,
                reported_stop,
                breakin_requested,
            },
            &mut self.registers,
        );
        Ok(())
    }

    /// Join the pump thread and take back ownership of the framing
    pub(super) fn reclaim_framing(&mut self) {
        if let Some(pump) = self.link.take_pump() {
            match pump.join.join() {
                // Whoever asked for the framing back also consumes the stop,
                // if there was one, and records it; until then the target is
                // still running.
                Ok(framing) => self.link = Link::RunningInline(framing),
                Err(_) => {
                    // The pump panicked; the framing (and socket) is lost. The
                    // next foreground op surfaces this as a transport error
                    kd_trace!("kd: pump: thread panicked, framing lost");
                }
            }
        }
    }

    /// Wait for the pump to report a stop. `wait` bounds a non-blocking poll;
    /// `None` blocks until the pump produces a stop. On a stop (or pump error)
    /// the framing is reclaimed and the pump handle dropped
    pub(super) fn take_pump_stop(&mut self, wait: Option<Duration>) -> Result<Option<StateChange>> {
        let Link::RunningPumped(pump) = &self.link else {
            return Ok(None);
        };
        let received = match wait {
            None => pump
                .stop_rx
                .recv()
                .map_err(|_| RecvTimeoutError::Disconnected),
            Some(timeout) => pump.stop_rx.recv_timeout(timeout),
        };
        match received {
            Ok(result) => {
                self.reclaim_framing();
                result.map(Some).map_err(Error::Kd)
            }
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                self.reclaim_framing();
                Err(Error::Kd("KD pump exited without reporting a stop".into()))
            }
        }
    }

    /// Stop the pump (if running) without waiting for a stop event, reclaiming
    /// the framing. Used on teardown and when abandoning an interrupt
    pub(super) fn shutdown_pump(&mut self) {
        let _ = self.shutdown_pump_with_stop();
    }

    fn try_recv_pump_stop(
        stop_rx: &mpsc::Receiver<std::result::Result<StateChange, String>>,
    ) -> Result<Option<StateChange>> {
        match stop_rx.try_recv() {
            Ok(Ok(stop)) => Ok(Some(stop)),
            Ok(Err(message)) => Err(Error::Kd(message)),
            Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => Ok(None),
        }
    }

    /// Stop the pump and return a stop it reported during shutdown, if any.
    pub(super) fn shutdown_pump_with_stop(&mut self) -> Result<Option<StateChange>> {
        let Some(pump) = self.link.take_pump() else {
            return Ok(None);
        };
        let PumpHandle {
            join,
            stop_rx,
            shutdown,
            reported_stop: _,
            breakin_requested: _,
        } = pump;
        shutdown.store(true, Ordering::SeqCst);
        // A reported error still leaves framing in the join value. Reclaim it
        // before propagating that error, just as we do for a successful stop.
        let stop = Self::try_recv_pump_stop(&stop_rx);
        match join.join() {
            Ok(framing) => self.link = Link::RunningInline(framing),
            Err(_) => {
                kd_trace!("kd: pump: thread panicked during shutdown, framing lost");
                if matches!(stop, Ok(None)) {
                    return Err(Error::Kd("KD pump thread panicked during shutdown".into()));
                }
            }
        }
        let stop = stop?;
        if stop.is_some() {
            return Ok(stop);
        }
        Self::try_recv_pump_stop(&stop_rx)
    }

    /// Send an unframed break-in byte over the cloned socket fd. Safe to call
    /// while the pump owns the framing for reading
    pub(super) fn send_raw_breakin(&mut self) -> Result<()> {
        self.breakin_clone.write_all(&[BREAKIN_BYTE])?;
        self.breakin_clone.flush()?;
        Ok(())
    }
}
