use crate::Iface;
use bitflags::bitflags;
use std::collections::{BTreeMap, VecDeque};
use std::{io, time};

bitflags! {
    pub(crate) struct Available: u8 {
        const READ = 0b00000001;
        const WRITE = 0b00000010;
    }
}

#[derive(Debug)]
enum State {
    //Listen,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
    CloseWait,
    Closing,
    LastAck,
    Closed,
}

impl State {
    #[allow(dead_code)] // for synchronized-state segment rules (RFC 793 S3.3), not yet wired up
    fn is_synchronized(&self) -> bool {
        match *self {
            State::SynRcvd => false,
            State::Estab
            | State::FinWait1
            | State::FinWait2
            | State::TimeWait
            | State::CloseWait
            | State::Closing
            | State::LastAck
            | State::Closed => true,
        }
    }
}

/// How long a fully-closed connection lingers in TIME-WAIT before the packet
/// loop reclaims it. Real stacks wait 2*MSL (up to 4 minutes) to catch peer
/// FIN retransmissions; shortened here so the reclamation is observable.
const TIME_WAIT: time::Duration = time::Duration::from_secs(10);

/// Receive buffer size; the window we advertise is the unused part of it.
const RECV_BUFFER: usize = 4096;

/// How long to wait for the peer's FIN after ours has been acknowledged
/// before giving up on the connection. Real stacks wait minutes; shortened
/// so the reclamation is observable.
const FIN_WAIT2_TIMEOUT: time::Duration = time::Duration::from_secs(30);

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
    timers: Timers,

    pub(crate) incoming: VecDeque<u8>,
    pub(crate) unacked: VecDeque<u8>,

    pub(crate) closed: bool,
    closed_at: Option<u32>,
    entered_timewait: Option<time::Instant>,
    entered_finwait2: Option<time::Instant>,
    /// set when the peer sent a RST; reads and writes must fail, not see EOF
    pub(crate) reset: bool,
    /// set when the application shut down its read side
    pub(crate) rcv_shutdown: bool,
}

struct Timers {
    send_times: BTreeMap<u32, time::Instant>,
    srtt: f64,
}

impl Connection {
    pub(crate) fn is_rcv_closed(&self) -> bool {
        // the application shut down its read side, or any state after
        // having received the peer's FIN
        if self.rcv_shutdown {
            return true;
        }
        if let State::TimeWait | State::CloseWait | State::Closing | State::LastAck | State::Closed =
            self.state
        {
            true
        } else {
            false
        }
    }

    /// half-close the receive side: further data from the peer is still
    /// acknowledged but discarded, and reads return EOF immediately
    pub(crate) fn shutdown_read(&mut self) {
        self.rcv_shutdown = true;
        self.incoming.clear();
    }

    /// the connection is fully closed and can be reclaimed by the packet loop
    pub(crate) fn is_done(&self) -> bool {
        if let State::Closed = self.state {
            true
        } else {
            false
        }
    }

    /// force the connection to CLOSED and fail outstanding reads/writes
    /// with ConnectionReset. The packet loop reclaims the connection once
    /// no stream still references it, so the reset keeps surfacing for as
    /// long as a handle exists.
    pub(crate) fn abort(&mut self) {
        self.state = State::Closed;
        self.reset = true;
    }

    fn availability(&self) -> Available {
        let mut a = Available::empty();
        if self.reset || self.is_rcv_closed() || !self.incoming.is_empty() {
            a |= Available::READ;
        }
        // there is room for more outgoing data, or the connection has
        // failed — either way a blocked writer should re-check
        if self.reset || self.unacked.len() < crate::SENDQUEUE_SIZE {
            a |= Available::WRITE;
        }
        // TODO: take into account self.state
        a
    }
}

/// State of the Send Sequence Space (RFC 793 S3.2 F4)
///
/// ```text
///            1         2          3          4
///       ----------|----------|----------|----------
///              SND.UNA    SND.NXT    SND.UNA
///                                   +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```
struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    #[allow(dead_code)] // part of the RFC 793 send state, not yet wired up
    up: bool,
    /// segment sequence number used for last window update
    wl1: u32,
    /// segment acknowledgment number used for last window update
    wl2: u32,
    /// initial send sequence number
    iss: u32,
}

/// State of the Receive Sequence Space (RFC 793 S3.2 F5)
///
/// ```text
///                1          2          3
///            ----------|----------|----------
///                   RCV.NXT    RCV.NXT
///                             +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
/// ```
struct RecvSequenceSpace {
    /// receive next
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    #[allow(dead_code)] // part of the RFC 793 receive state, not yet wired up
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept<'a>(
        nic: &mut Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        _data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        if !tcph.syn() {
            // only expected SYN packet
            return Ok(None);
        }

        let iss = 0;
        // our advertised receive window starts as the full receive buffer;
        // it is recomputed from `incoming` on every outgoing segment
        let wnd = RECV_BUFFER as u16;
        let mut c = Connection {
            timers: Timers {
                send_times: Default::default(),
                // start at the retransmit floor: a huge initial estimate
                // (this used to be 60s) makes the first loss on every
                // connection wait ~1.5x that before retransmitting
                srtt: time::Duration::from_secs(1).as_secs_f64(),
            },
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss,
                // the peer's advertised window — how much we may send —
                // updated from ACKs per the SND.WL1/WL2 rules
                wnd: tcph.window_size(),
                up: false,

                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number() + 1,
                wnd: wnd,
                up: false,
            },
            tcp: etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(), iss, wnd),
            ip: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpTrafficClass::Tcp,
                [
                    iph.destination()[0],
                    iph.destination()[1],
                    iph.destination()[2],
                    iph.destination()[3],
                ],
                [
                    iph.source()[0],
                    iph.source()[1],
                    iph.source()[2],
                    iph.source()[3],
                ],
            ),

            incoming: Default::default(),
            unacked: Default::default(),

            closed: false,
            closed_at: None,
            entered_timewait: None,
            entered_finwait2: None,
            reset: false,
            rcv_shutdown: false,
        };

        // need to start establishing a connection
        c.tcp.syn = true;
        c.tcp.ack = true;
        c.write(nic, c.send.nxt, 0)?;
        Ok(Some(c))
    }

    fn write(&mut self, nic: &mut Iface, seq: u32, mut limit: usize) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        self.tcp.sequence_number = seq;
        self.tcp.acknowledgment_number = self.recv.nxt;

        // advertise the unused part of the receive buffer as our window
        // (RCV.WND, RFC 793 S3.1); the sequence-space check uses the same
        // value, so acceptance and advertisement cannot disagree.
        //
        // NOTE: we never send spontaneous window updates (no persist timer);
        // when we advertise 0 and the application later drains `incoming`,
        // it is the peer's zero-window probes — which fail the sequence
        // check and land in the bare-ACK path — that re-open the window
        // through this recomputation
        let space = RECV_BUFFER.saturating_sub(self.incoming.len());
        self.recv.wnd = space as u16;
        self.tcp.window_size = space as u16;

        // TODO: return +1 for SYN/FIN
        println!(
            "write(ack: {}, seq: {}, limit: {}) syn {:?} fin {:?}",
            self.recv.nxt - self.recv.irs, seq, limit, self.tcp.syn, self.tcp.fin,
        );

        let mut offset = seq.wrapping_sub(self.send.una) as usize;
        // we need to special-case the two "virtual" bytes SYN and FIN
        if let Some(closed_at) = self.closed_at {
            if seq == closed_at.wrapping_add(1) {
                // trying to write following FIN
                offset = 0;
                limit = 0;
            }
        }
        println!(
            "using offset {} base {} in {:?}",
            offset,
            self.send.una,
            self.unacked.as_slices()
        );
        let (mut h, mut t) = self.unacked.as_slices();
        if h.len() >= offset {
            h = &h[offset..];
        } else {
            let skipped = h.len();
            h = &[];
            t = &t[(offset - skipped)..];
        }

        let max_data = std::cmp::min(limit, h.len() + t.len());
        let size = std::cmp::min(
            buf.len(),
            self.tcp.header_len() as usize + self.ip.header_len() as usize + max_data,
        );
        let _ = self.ip.set_payload_len(size - self.ip.header_len() as usize);

        // write out the headers and the payload
        use std::io::Write;
        let buf_len = buf.len();
        let mut unwritten = &mut buf[..];

        let _ = self.ip.write(&mut unwritten);
        let ip_header_ends_at = buf_len - unwritten.len();

        // postpone writing the tcp header because we need the payload as one contiguous slice to calculate the tcp checksum
        unwritten = &mut unwritten[self.tcp.header_len() as usize..];
        let tcp_header_ends_at = buf_len - unwritten.len();

        // write out the payload
        let payload_bytes = {
            let mut written = 0;
            let mut limit = max_data;

            // first, write as much as we can from h
            let p1l = std::cmp::min(limit, h.len());
            written += unwritten.write(&h[..p1l])?;
            limit -= written;

            // then, write more (if we can) from t
            let p2l = std::cmp::min(limit, t.len());
            written += unwritten.write(&t[..p2l])?;
            written
        };
        let payload_ends_at = buf_len - unwritten.len();

        // finally we can calculate the tcp checksum and write out the tcp header
        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &buf[tcp_header_ends_at..payload_ends_at])
            .expect("failed to compute checksum");

        let mut tcp_header_buf = &mut buf[ip_header_ends_at..tcp_header_ends_at];
        let _ = self.tcp.write(&mut tcp_header_buf);

        let mut next_seq = seq.wrapping_add(payload_bytes as u32);
        if self.tcp.syn {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.fin = false;
        }
        if wrapping_lt(self.send.nxt, next_seq) {
            self.send.nxt = next_seq;
        }
        self.timers.send_times.insert(seq, time::Instant::now());

        nic.send(&buf[..payload_ends_at])?;
        Ok(payload_bytes)
    }

    #[allow(dead_code)] // will be wired to the RST paths noted in its TODOs
    fn send_rst(&mut self, nic: &mut Iface) -> io::Result<()> {
        self.tcp.rst = true;
        // TODO: fix sequence numbers here
        // If the incoming segment has an ACK field, the reset takes its
        // sequence number from the ACK field of the segment, otherwise the
        // reset has sequence number zero and the ACK field is set to the sum
        // of the sequence number and segment length of the incoming segment.
        // The connection remains in the same state.
        //
        // TODO: handle synchronized RST
        // 3.  If the connection is in a synchronized state (ESTABLISHED,
        // FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT),
        // any unacceptable segment (out of window sequence number or
        // unacceptible acknowledgment number) must elicit only an empty
        // acknowledgment segment containing the current send-sequence number
        // and an acknowledgment indicating the next sequence number expected
        // to be received, and the connection remains in the same state.
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, self.send.nxt, 0)?;
        Ok(())
    }

    pub(crate) fn on_tick(&mut self, nic: &mut Iface) -> io::Result<Available> {
        if let State::FinWait2 = self.state {
            // we have shutdown our write side and the other side acked, no
            // need to (re)transmit anything. If the peer never sends its
            // FIN, give up on the connection after the timeout above.
            if self
                .entered_finwait2
                .map(|t| t.elapsed() > FIN_WAIT2_TIMEOUT)
                .unwrap_or(false)
            {
                self.state = State::Closed;
            }
            return Ok(self.availability());
        }

        if let State::TimeWait = self.state {
            // linger briefly to catch peer FIN retransmissions, then let the
            // packet loop reclaim the connection
            if self
                .entered_timewait
                .map(|t| t.elapsed() > TIME_WAIT)
                .unwrap_or(false)
            {
                self.state = State::Closed;
            }
            return Ok(self.availability());
        }

        if let State::Closed = self.state {
            return Ok(self.availability());
        }

        // eprintln!("ON TICK: state {:?} una {} nxt {} unacked {:?}",
        //           self.state, self.send.una, self.send.nxt, self.unacked);

        // count only real data bytes in flight: the SYN and FIN occupy
        // sequence numbers but not the unacked buffer, and leaving them in
        // made this underflow (and flood the peer with empty segments)
        let mut nunacked_data = self.send.nxt.wrapping_sub(self.send.una);
        if self.send.una == self.send.iss {
            // our SYN has not been acknowledged yet
            nunacked_data -= 1;
        }
        if let Some(closed_at) = self.closed_at {
            if wrapping_lt(self.send.una, closed_at.wrapping_add(1)) {
                // our FIN has not been acknowledged yet
                nunacked_data -= 1;
            }
        }
        debug_assert!(
            nunacked_data <= self.unacked.len() as u32,
            "in-flight data exceeds queued data"
        );
        let nunsent_data = self.unacked.len() as u32 - nunacked_data;

        let waited_for = self
            .timers
            .send_times
            .range(self.send.una..)
            .next()
            .map(|t| t.1.elapsed());

        let should_retransmit = if let Some(waited_for) = waited_for {
            waited_for > time::Duration::from_secs(1)
                && waited_for.as_secs_f64() > 1.5 * self.timers.srtt
        } else {
            false
        };

        if should_retransmit {
            let resend = std::cmp::min(self.unacked.len() as u32, self.send.wnd as u32);
            if resend < self.send.wnd as u32 && self.closed {
                // can we include the FIN?
                self.tcp.fin = true;
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
            }
            if self.send.una == self.send.iss {
                // what we are retransmitting is our unacknowledged SYN;
                // write() cleared the flag after the first transmission
                self.tcp.syn = true;
            }
            self.write(nic, self.send.una, resend as usize)?;
        } else {
            // we should send new data if we have new data and space in the window
            // (nothing to do when idle, or once everything incl. our FIN is
            // in flight; a scheduled-but-unsent FIN still needs sending)
            if nunsent_data == 0 && (!self.closed || self.closed_at.is_some()) {
                return Ok(self.availability());
            }

            // saturating: the peer may have shrunk its window below what we
            // already have in flight; send nothing new until it opens again
            let allowed = (self.send.wnd as u32).saturating_sub(nunacked_data);
            if allowed == 0 {
                return Ok(self.availability());
            }

            let send = std::cmp::min(nunsent_data, allowed);
            if send < allowed && self.closed && self.closed_at.is_none() {
                self.tcp.fin = true;
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
            }

            self.write(nic, self.send.nxt, send as usize)?;
        }

        Ok(self.availability())
    }

    pub(crate) fn on_packet<'a>(
        &mut self,
        nic: &mut Iface,
        _iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Available> {
        // first, check that sequence numbers are valid (RFC 793 S3.3)
        let seqn = tcph.sequence_number();
        let mut slen = data.len() as u32;
        if tcph.fin() {
            slen += 1;
        };
        if tcph.syn() {
            slen += 1;
        };
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let okay = if slen == 0 {
            // zero-length segment has separate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    false
                } else {
                    true
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                false
            } else {
                true
            }
        } else {
            if self.recv.wnd == 0 {
                false
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    wend,
                )
            {
                false
            } else {
                true
            }
        };

        if !okay {
            if tcph.rst() {
                // RFC 793 S3.4: a RST outside the window is silently discarded
                return Ok(self.availability());
            }
            eprintln!("NOT OKAY");
            if let State::SynRcvd = self.state {
                if tcph.syn() && seqn == self.recv.irs {
                    // the peer is retransmitting its SYN because our SYN-ACK
                    // was lost: resend the SYN-ACK (write() cleared the SYN
                    // flag after the first transmission)
                    self.tcp.syn = true;
                    self.write(nic, self.send.iss, 0)?;
                    return Ok(self.availability());
                }
            }
            self.write(nic, self.send.nxt, 0)?;
            return Ok(self.availability());
        }

        if tcph.rst() {
            // the peer has aborted the connection (RFC 793 S3.4 "reset
            // processing"); discard any buffered data — the read side must
            // see an error, not a clean EOF.
            //
            // NOTE: the sequence check above gates this, which is right for
            // synchronized states; in SYN-RCVD the RFC would check RST
            // first — an accepted simplification in this stack.
            eprintln!("got RST; aborting connection");
            self.incoming.clear();
            self.abort();
            return Ok(self.availability());
        }

        if !tcph.ack() {
            if tcph.syn() {
                // got SYN part of initial handshake
                assert!(data.is_empty());
                self.recv.nxt = seqn.wrapping_add(1);
            }
            return Ok(self.availability());
        }

        let ackn = tcph.acknowledgment_number();
        if let State::SynRcvd = self.state {
            if is_between_wrapped(
                self.send.una.wrapping_sub(1),
                ackn,
                self.send.nxt.wrapping_add(1),
            ) {
                // must have ACKed our SYN, since we detected at least one acked byte,
                // and we have only sent one byte (the SYN).
                self.state = State::Estab;
            } else {
                // TODO: <SEQ=SEG.ACK><CTL=RST>
            }
        }

        if let State::Estab
        | State::FinWait1
        | State::FinWait2
        | State::CloseWait
        | State::Closing
        | State::LastAck = self.state
        {
            if is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                println!(
                    "ack for {} (last: {}); prune in {:?}",
                    ackn, self.send.una, self.unacked
                );
                if !self.unacked.is_empty() {
                    let data_start = if self.send.una == self.send.iss {
                        // send.una hasn't been updated yet with ACK for our SYN, so data starts just beyond it
                        self.send.una.wrapping_add(1)
                    } else {
                        self.send.una
                    };
                    let acked_data_end = std::cmp::min(ackn.wrapping_sub(data_start) as usize, self.unacked.len());
                    self.unacked.drain(..acked_data_end);

                    let old = std::mem::replace(&mut self.timers.send_times, BTreeMap::new());

                    let una = self.send.una;
                    let srtt = &mut self.timers.srtt;
                    self.timers
                        .send_times
                        .extend(old.into_iter().filter_map(|(seq, sent)| {
                            if is_between_wrapped(una, seq, ackn) {
                                *srtt = 0.8 * *srtt + (1.0 - 0.8) * sent.elapsed().as_secs_f64();
                                None
                            } else {
                                Some((seq, sent))
                            }
                        }));
                }
                self.send.una = ackn;
            }

            // update the send window per RFC 793 S3.3: SEG.SEQ > SND.WL1, or
            // SEG.SEQ == SND.WL1 and SEG.ACK >= SND.WL2. This must NOT be
            // gated on SEG.ACK advancing SND.UNA: a pure window update
            // (SEG.ACK == SND.UNA with a larger window) is exactly how a
            // peer re-opens a zero window, and the WL1/WL2 comparison above
            // is what rejects stale duplicates
            if wrapping_lt(self.send.wl1, seqn)
                || (seqn == self.send.wl1 && !wrapping_lt(ackn, self.send.wl2))
            {
                self.send.wnd = tcph.window_size();
                self.send.wl1 = seqn;
                self.send.wl2 = ackn;
            }
        }

        if let State::FinWait1 = self.state {
            if let Some(closed_at) = self.closed_at {
                if self.send.una == closed_at.wrapping_add(1) {
                    // our FIN has been ACKed!
                    self.state = State::FinWait2;
                    self.entered_finwait2 = Some(time::Instant::now());
                }
            }
        }

        if let State::Closing = self.state {
            if let Some(closed_at) = self.closed_at {
                if self.send.una == closed_at.wrapping_add(1) {
                    // simultaneous close: our FIN has been ACKed too
                    self.state = State::TimeWait;
                    self.entered_timewait = Some(time::Instant::now());
                }
            }
        }

        if let State::LastAck = self.state {
            if let Some(closed_at) = self.closed_at {
                if self.send.una == closed_at.wrapping_add(1) {
                    // passive close finished: our FIN has been ACKed
                    self.state = State::Closed;
                }
            }
        }

        if !data.is_empty() {
            if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
                if self.rcv_shutdown {
                    // our read side is shut: the peer cannot know and keeps
                    // sending. Take responsibility for the data (RCV.NXT
                    // advances, the segment is ACKed, the window stays open)
                    // but discard it — reads must keep returning EOF
                    self.recv.nxt = seqn.wrapping_add(data.len() as u32);
                } else {
                    if wrapping_lt(self.recv.nxt, seqn) {
                        // out-of-order segment: a gap of unreceived data
                        // precedes it. Buffer nothing and never advance RCV.NXT
                        // across the gap — re-ACK the left edge (dup-ACK) so the
                        // peer retransmits what is missing. Without this, the
                        // ACK would take credit for the missing bytes and they
                        // would be lost silently.
                        self.write(nic, self.send.nxt, 0)?;
                        return Ok(self.availability());
                    }

                    let mut unread_data_at = self.recv.nxt.wrapping_sub(seqn) as usize;
                    if unread_data_at > data.len() {
                        // a fully-consumed retransmission: a later segment
                        // already advanced RCV.NXT past this segment's data,
                        // so nothing in here is new
                        unread_data_at = data.len();
                    }
                    self.incoming.extend(&data[unread_data_at..]);

                    /*
                    Once the TCP takes responsibility for the data it advances
                    RCV.NXT over the data accepted, and adjusts RCV.WND as
                    apporopriate to the current buffer availability.  The total of
                    RCV.NXT and RCV.WND should not be reduced.
                     */
                    let new_nxt = seqn.wrapping_add(data.len() as u32);
                    if wrapping_lt(self.recv.nxt, new_nxt) {
                        // never move RCV.NXT backwards (fully-consumed
                        // retransmissions must not rewind it)
                        self.recv.nxt = new_nxt;
                    }
                }

                // Send an acknowledgment of the form: <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                // TODO: maybe just tick to piggyback ack on data?
                self.write(nic, self.send.nxt, 0)?;
            }
        }

        if tcph.fin() {
            match self.state {
                State::FinWait2 => {
                    // we're done with the connection!
                    self.recv.nxt = self.recv.nxt.wrapping_add(1);
                    self.write(nic, self.send.nxt, 0)?;
                    self.state = State::TimeWait;
                    self.entered_timewait = Some(time::Instant::now());
                }
                State::Estab => {
                    // passive close: the peer is done sending, but we may not be
                    self.recv.nxt = self.recv.nxt.wrapping_add(1);
                    self.write(nic, self.send.nxt, 0)?;
                    self.state = State::CloseWait;
                }
                State::FinWait1 => {
                    // simultaneous close: our FIN is still unacknowledged
                    self.recv.nxt = self.recv.nxt.wrapping_add(1);
                    self.write(nic, self.send.nxt, 0)?;
                    self.state = State::Closing;
                }
                State::TimeWait
                | State::CloseWait
                | State::Closing
                | State::LastAck
                | State::Closed => {
                    // duplicate FIN (RCV.NXT already covers it); just re-ACK
                    self.write(nic, self.send.nxt, 0)?;
                }
                _ => {}
            }
        }

        Ok(self.availability())
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        match self.state {
            State::SynRcvd | State::Estab => {
                self.state = State::FinWait1;
            }
            State::FinWait1 | State::FinWait2 | State::Closing => {}
            State::CloseWait => {
                // passive close: we already saw the peer's FIN; once ours is
                // ACKed the connection is finished
                self.state = State::LastAck;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "already closing",
                ))
            }
        };
        Ok(())
    }
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // From RFC1323:
    //     TCP determines if a data segment is "old" or "new" by testing
    //     whether its sequence number is within 2**31 bytes of the left edge
    //     of the window, and if it is not, discarding the data as "old".  To
    //     insure that new data is never mistakenly considered old and vice-
    //     versa, the left edge of the sender's window has to be at most
    //     2**31 away from the right edge of the receiver's window.
    lhs.wrapping_sub(rhs) > (1 << 31)
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn_in(state: State) -> Connection {
        Connection {
            state,
            send: SendSequenceSpace {
                iss: 1000,
                una: 1000,
                nxt: 1000,
                wnd: 1024,
                up: false,
                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                nxt: 5000,
                wnd: 1024,
                up: false,
                irs: 4999,
            },
            ip: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpTrafficClass::Tcp,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
            ),
            tcp: etherparse::TcpHeader::new(8000, 9000, 1000, 1024),
            timers: Timers {
                send_times: BTreeMap::new(),
                srtt: 60.0,
            },
            incoming: Default::default(),
            unacked: Default::default(),
            closed: false,
            closed_at: None,
            entered_timewait: None,
            entered_finwait2: None,
            reset: false,
            rcv_shutdown: false,
        }
    }

    #[test]
    fn wrapping_lt_basics() {
        assert!(!wrapping_lt(5, 5));
        assert!(wrapping_lt(5, 6));
        assert!(!wrapping_lt(6, 5));
        // crossing the 2^32 boundary
        assert!(wrapping_lt(0xFFFFFFF0, 0x10));
        assert!(!wrapping_lt(0x10, 0xFFFFFFF0));
    }

    #[test]
    fn wrapping_lt_half_domain_boundary() {
        // exactly 2^31 apart is on the boundary and not "less" (RFC 1323)
        assert!(!wrapping_lt(0, 1 << 31));
        assert!(!wrapping_lt(1 << 31, 0));
        // just under 2^31 apart is less, in both wrap directions
        assert!(wrapping_lt(0, (1 << 31) - 1));
        assert!(wrapping_lt((1 << 31) + 1, 0));
    }

    #[test]
    fn is_between_wrapped_cases() {
        assert!(is_between_wrapped(0, 1, 10));
        // both ends are exclusive
        assert!(!is_between_wrapped(0, 0, 10));
        assert!(!is_between_wrapped(0, 10, 10));
        assert!(!is_between_wrapped(0, 11, 10));
        // windows spanning the 2^32 boundary
        assert!(is_between_wrapped(0xFFFFFFF8, 5, 16));
        assert!(!is_between_wrapped(5, 0xFFFFFFF8, 16));
    }

    #[test]
    fn states_after_peer_fin_are_rcv_closed() {
        let closed = [
            State::CloseWait,
            State::Closing,
            State::TimeWait,
            State::LastAck,
            State::Closed,
        ];
        for state in closed {
            let name = format!("{:?}", state);
            assert!(conn_in(state).is_rcv_closed(), "{} should be rcv-closed", name);
        }
        let open = [
            State::SynRcvd,
            State::Estab,
            State::FinWait1,
            State::FinWait2,
        ];
        for state in open {
            let name = format!("{:?}", state);
            assert!(!conn_in(state).is_rcv_closed(), "{} should not be rcv-closed", name);
        }
    }

    #[test]
    fn only_closed_is_done() {
        assert!(conn_in(State::Closed).is_done());
        let not_done = [
            State::SynRcvd,
            State::Estab,
            State::FinWait1,
            State::FinWait2,
            State::TimeWait,
            State::CloseWait,
            State::Closing,
            State::LastAck,
        ];
        for state in not_done {
            let name = format!("{:?}", state);
            assert!(!conn_in(state).is_done(), "{} is not done", name);
        }
    }

    #[test]
    fn synchronized_states() {
        assert!(!conn_in(State::SynRcvd).state.is_synchronized());
        let synced = [
            State::Estab,
            State::FinWait1,
            State::FinWait2,
            State::TimeWait,
            State::CloseWait,
            State::Closing,
            State::LastAck,
            State::Closed,
        ];
        for state in synced {
            let name = format!("{:?}", state);
            assert!(conn_in(state).state.is_synchronized(), "{} is synchronized", name);
        }
    }

    #[test]
    fn abort_closes_and_resets() {
        let mut c = conn_in(State::Estab);
        c.abort();
        assert!(matches!(c.state, State::Closed));
        assert!(c.reset);
        assert!(c.is_done());
        assert!(c.is_rcv_closed());
    }

    #[test]
    fn shutdown_read_closes_rcv_side_and_discards() {
        let mut c = conn_in(State::Estab);
        c.incoming.extend(b"abc".iter());
        assert!(!c.is_rcv_closed());
        c.shutdown_read();
        assert!(c.is_rcv_closed());
        assert!(c.incoming.is_empty());
        // idempotent
        c.shutdown_read();
        assert!(c.is_rcv_closed());
    }

    #[test]
    fn close_transitions() {
        // active close
        let mut c = conn_in(State::Estab);
        c.close().unwrap();
        assert!(matches!(c.state, State::FinWait1));
        assert!(c.closed);

        let mut c = conn_in(State::SynRcvd);
        c.close().unwrap();
        assert!(matches!(c.state, State::FinWait1));
        assert!(c.closed);

        // passive close
        let mut c = conn_in(State::CloseWait);
        c.close().unwrap();
        assert!(matches!(c.state, State::LastAck));
        assert!(c.closed);

        // already closing: idempotent
        let mut c = conn_in(State::FinWait1);
        c.close().unwrap();
        assert!(matches!(c.state, State::FinWait1));

        let mut c = conn_in(State::FinWait2);
        c.close().unwrap();
        assert!(matches!(c.state, State::FinWait2));

        let mut c = conn_in(State::Closing);
        c.close().unwrap();
        assert!(matches!(c.state, State::Closing));

        // fully closing/closed: error
        assert!(conn_in(State::TimeWait).close().is_err());
        assert!(conn_in(State::LastAck).close().is_err());
        assert!(conn_in(State::Closed).close().is_err());
    }
}
