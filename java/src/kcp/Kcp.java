package kcp;

import java.util.Arrays;

/**
 * KCP - A Better ARQ Protocol Implementation
 * <p>Features:
 * <li>Average RTT reduce 30% - 40% vs traditional ARQ like tcp.
 * <li>Maximum RTT reduce three times vs tcp.
 * <li>Lightweight, distributed as a single source file.
 * <p>Imports: System.out.printf; System.arraycopy; Arrays.copyOf; Integer.MAX_VALUE; Math.min; Math.max; Math.abs
 * <p>Usage: new->update(flush)->check; send->update(flush)->check; input->peeksize->recv->update(flush)->check
 */
public abstract class Kcp {
	public static final int IKCP_LOG_OUTPUT = 0x1;
	public static final int IKCP_LOG_INPUT = 0x2;
	public static final int IKCP_LOG_RECV = 0x8;
	public static final int IKCP_LOG_IN_DATA = 0x10;
	public static final int IKCP_LOG_IN_ACK = 0x20;
	public static final int IKCP_LOG_IN_PROBE = 0x40;
	public static final int IKCP_LOG_IN_WINS = 0x80;
	// KCP BASIC
	public static final boolean IKCP_FASTACK_CONSERVE = false;
	public static final int IKCP_RTO_NDL = 30;         // no delay min rto
	public static final int IKCP_RTO_MIN = 100;        // normal min rto
	public static final int IKCP_RTO_DEF = 200;
	public static final int IKCP_RTO_MAX = 60000;
	public static final int IKCP_CMD_PUSH = 81;        // cmd: push data
	public static final int IKCP_CMD_ACK = 82;         // cmd: ack
	public static final int IKCP_CMD_WASK = 83;        // cmd: window probe (ask)
	public static final int IKCP_CMD_WINS = 84;        // cmd: window size (tell)
	public static final int IKCP_ASK_SEND = 0x1;       // need to send IKCP_CMD_WASK
	public static final int IKCP_ASK_TELL = 0x2;       // need to send IKCP_CMD_WINS
	public static final int IKCP_WND_SND = 32;
	public static final int IKCP_WND_RCV = 128;        // must in [max fragment size,257]
	public static final int IKCP_MTU_DEF = 1400;       // must in [IKCP_OVERHEAD+1,0x7fff]
	public static final int IKCP_INTERVAL = 100;
	public static final int IKCP_OVERHEAD = 24;
	public static final int IKCP_DEADLINK = 20;
	public static final int IKCP_THRESH_INIT = 2;
	public static final int IKCP_THRESH_MIN = 2;
	public static final int IKCP_PROBE_INIT = 7000;    // 7 secs to probe window size
	public static final int IKCP_PROBE_LIMIT = 120000; // up to 120 secs to probe window
	public static final int IKCP_FASTACK_LIMIT = 5;    // max times to trigger fastack
	// struct IKCPCB
	private final int conv;
	private final int mss; // mtu-IKCP_OVERHEAD [1,0x7fff-IKCP_OVERHEAD]
	private int snd_una;   // uint32_t
	private int snd_nxt;   // uint32_t
	private int rcv_nxt;   // uint32_t
	private int ssthresh = IKCP_THRESH_INIT; // uint32_t
	private int rx_rttval;
	private int rx_srtt;
	private int rx_rto = IKCP_RTO_DEF;
	private int rx_minrto = IKCP_RTO_MIN;
	private int snd_wnd = IKCP_WND_SND; // uint32_t [1,]
	private int rcv_wnd = IKCP_WND_RCV; // uint32_t [IKCP_WND_RCV,]
	private int rmt_wnd = IKCP_WND_RCV; // uint32_t [0,0xffff]
	private int cwnd;    // uint32_t
	private int current; // uint32_t
	private int interval = IKCP_INTERVAL; // uint32_t
	private int ts_flush;   // uint32_t
	private int nsnd_buf;   // uint32_t
	private int nrcv_que;   // uint32_t
	private int nsnd_que;   // uint32_t
	private int ts_probe;   // uint32_t
	private int probe_wait; // uint32_t
	private int incr;       // uint32_t
	private final KcpSeg snd_buf = new KcpSeg();   // input, check(R), flush
	private final KcpSeg snd_queue = new KcpSeg(); // send, update->flush
	private final KcpSeg rcv_buf = new KcpSeg();   // input, recv
	private final KcpSeg rcv_queue = new KcpSeg(); // input, recv, peeksize(R)
	private int ackcount;  // uint32_t
	private int[] acklist = new int[16]; // uint32_t*
	protected final byte[] buffer;
	private int fastresend = Integer.MAX_VALUE;
	private byte logmask;
	private byte probe; // flags: IKCP_ASK_SEND, IKCP_ASK_TELL
	private byte nodelay; // [0,2]
	private final boolean stream; // send
	private boolean nocwnd;

	static void encode8u(byte[] b, int p, byte v) {
		b[p] = v;
	}

	static void encode16u(byte[] b, int p, short v) {
		b[p] = (byte)v;
		b[p + 1] = (byte)(v >> 8);
	}

	static void encode32u(byte[] b, int p, int v) {
		b[p] = (byte)v;
		b[p + 1] = (byte)(v >> 8);
		b[p + 2] = (byte)(v >> 16);
		b[p + 3] = (byte)(v >> 24);
	}

	static int decode8u(byte[] b, int p) {
		return b[p] & 0xff;
	}

	static int decode16u(byte[] b, int p) {
		return (b[p] & 0xff) + ((b[p + 1] & 0xff) << 8);
	}

	static int decode32u(byte[] b, int p) {
		return (b[p] & 0xff) + ((b[p + 1] & 0xff) << 8) + ((b[p + 2] & 0xff) << 16) + (b[p + 3] << 24);
	}

	private void encode_seg(int pos, KcpSeg seg) {
		final byte[] buf = buffer;
		encode32u(buf, pos, conv);
		encode8u(buf, pos + 4, seg.cmd);
		encode8u(buf, pos + 5, seg.frg);
		encode16u(buf, pos + 6, seg.wnd);
		encode32u(buf, pos + 8, seg.ts);
		encode32u(buf, pos + 12, seg.sn);
		encode32u(buf, pos + 16, seg.una);
		encode32u(buf, pos + 20, seg.len);
	}

	/**
	 * create a new kcp control object, 'conv' must equal in two endpoint from the same connection.
	 */
	public Kcp(final int conv, final int current, int mtu, final byte[] buffer, final boolean stream) {
		if (mtu <= IKCP_OVERHEAD || mtu > 0x7fff)
			mtu = IKCP_MTU_DEF;
		this.conv = conv;
		this.stream = stream;
		mss = mtu - IKCP_OVERHEAD;
		this.buffer = buffer != null && buffer.length >= mtu ? buffer : new byte[mtu];
		ts_flush = current + interval;
		flush(current);
	}

	public final int conv() { // const
		return conv;
	}

	public final boolean lost() {
		for (KcpSeg p = snd_buf.next(); p != snd_buf; p = p.next())
			if (p.xmit < 0 || p.xmit >= IKCP_DEADLINK)
				return true;
		return false;
	}

	public final void logmask(final int logmask) {
		this.logmask = (byte)logmask;
	}

	private boolean canlog(final int mask) { // const
		return (mask & logmask) != 0;
	}

	@SuppressWarnings("MethodMayBeStatic")
	public void log(String format, Object... args) { // flush, input, recv
		System.out.printf(format + "%n", args);
	}

	public KcpSeg allocSeg(int size) { // send, input
		return new KcpSeg(size);
	}

	public void freeSeg(@SuppressWarnings("unused") KcpSeg seg) {
	}

	final void rx_minrto(final int rx_minrto) {
		if (rx_minrto >= 0)
			this.rx_minrto = rx_minrto;
	}

	final void fastresend(final int fastresend) {
		this.fastresend = fastresend > 0 ? fastresend : Integer.MAX_VALUE;
	}

	/**
	 * fastest: nodelay(1, 20, 2, 1)
	 * @param nodelay 0:disable(default), 1:enable
	 * @param interval internal update timer interval in millisec, default is 100ms
	 * @param resend 0:disable fast resend(default), 1:enable fast resend
	 * @param nc 0:normal congestion control(default), 1:disable congestion control
	 */
	public final void nodelay(final int nodelay, final int interval, final int resend, final int nc) {
		if (nodelay >= 0) {
			this.nodelay = (byte)(nodelay & 0x7f);
			rx_minrto(nodelay != 0 ? IKCP_RTO_NDL : IKCP_RTO_MIN);
		}
		if (interval >= 0)
			this.interval = Math.min(Math.max(interval, 10), 5000);
		if (resend >= 0)
			fastresend(resend);
		if (nc >= 0)
			nocwnd = nc != 0;
	}

	/**
	 * set maximum window size: sndwnd=32, rcvwnd=128 by default
	 */
	public final void wndsize(final int sndwnd, final int rcvwnd) {
		if (sndwnd > 0)
			snd_wnd = sndwnd;
		if (rcvwnd > 0) // must >= max fragment size
			rcv_wnd = Math.max(rcvwnd, IKCP_WND_RCV);
	}

	/**
	 * get how many packet is waiting to be sent
	 */
	public final int waitsnd() { // const
		return nsnd_buf + nsnd_que;
	}

	/**
	 * output callback, which will be invoked by kcp
	 */
	public abstract void output(int len); // const

	private void output0(final int len) { // const, flush
		if (canlog(IKCP_LOG_OUTPUT))
			log("[RO] %d bytes", len);
		if (len > 0)
			output(len);
	}

	/**
	 * user/upper level send, returns below zero for error
	 */
	public final int send(final byte[] buf, int pos, int len) {
		if (len < 0)
			return -1;

		if (stream) { // append to previous segment in streaming mode (if possible)
			if (!snd_queue.isEmpty()) {
				final KcpSeg old = snd_queue.prev();
				final int oldlen = old.len;
				if (oldlen < mss) {
					final int extend = Math.min(len, mss - oldlen);
					final int newlen = oldlen + extend;
					final KcpSeg seg;
					if (old.data.length >= newlen)
						seg = old;
					else {
						seg = allocSeg(newlen);
						seg.linkTail(snd_queue);
						System.arraycopy(old.data, 0, seg.data, 0, oldlen);
						old.unlink();
						freeSeg(old);
					}
					if (extend > 0) {
						System.arraycopy(buf, pos, seg.data, oldlen, extend);
						pos += extend;
					}
					seg.len = newlen;
					seg.frg = 0;
					len -= extend;
				}
			}
			if (len <= 0)
				return 0;
		}
		final int count = Math.max((len + mss - 1) / mss, 1);
		if (count >= IKCP_WND_RCV)
			return -2;

		// fragment
		for (int i = 0; i < count; i++) { // count:[1,IKCP_WND_RCV-1]
			final int size = Math.min(len, mss);
			final KcpSeg seg = allocSeg(size);
			if (size > 0) {
				System.arraycopy(buf, pos, seg.data, 0, size);
				pos += size;
			}
			seg.len = size;
			seg.frg = stream ? 0 : (byte)(count - i - 1);
			seg.linkTail(snd_queue);
			nsnd_que++;
			len -= size;
		}
		return 0;
	}

	/**
	 * flush pending data
	 */
	public final void flush(final int current) {
		this.current = current;
		final KcpSeg seg = snd_buf;
		seg.cmd = IKCP_CMD_ACK;
		// seg.frg = 0;
		seg.wnd = (short)Math.max(rcv_wnd - nrcv_que, 0);
		seg.ts = 0;
		seg.sn = 0;
		seg.una = rcv_nxt;
		// seg.len = 0;

		// flush acknowledges
		int pos = 0;
		final int count = ackcount;
		for (int i = 0; i < count; i++) {
			if (pos > mss) {
				output0(pos);
				pos = 0;
			}
			seg.sn = acklist[i * 2];
			seg.ts = acklist[i * 2 + 1];
			encode_seg(pos, seg);
			pos += IKCP_OVERHEAD;
		}
		ackcount = 0;

		// probe window size (if remote window size equals zero)
		if (rmt_wnd == 0) {
			if (probe_wait == 0) {
				probe_wait = IKCP_PROBE_INIT;
				ts_probe = current + probe_wait;
			} else {
				if (current - ts_probe >= 0) {
					if (probe_wait < IKCP_PROBE_INIT)
						probe_wait = IKCP_PROBE_INIT;
					probe_wait += probe_wait / 2;
					if (probe_wait > IKCP_PROBE_LIMIT)
						probe_wait = IKCP_PROBE_LIMIT;
					ts_probe = current + probe_wait;
					probe |= IKCP_ASK_SEND;
				}
			}
		} else {
			ts_probe = 0;
			probe_wait = 0;
		}

		// flush window probing commands
		if ((probe & IKCP_ASK_SEND) != 0) {
			seg.cmd = IKCP_CMD_WASK;
			if (pos > mss) {
				output0(pos);
				pos = 0;
			}
			encode_seg(pos, seg);
			pos += IKCP_OVERHEAD;
		}

		// flush window probing commands
		if ((probe & IKCP_ASK_TELL) != 0) {
			seg.cmd = IKCP_CMD_WINS;
			if (pos > mss) {
				output0(pos);
				pos = 0;
			}
			encode_seg(pos, seg);
			pos += IKCP_OVERHEAD;
		}
		probe = 0;

		// calculate window size
		int cwnd = Math.min(snd_wnd, rmt_wnd);
		if (!nocwnd && cwnd > this.cwnd)
			cwnd = this.cwnd;

		// move data from snd_queue to snd_buf
		while (snd_nxt - (snd_una + cwnd) < 0) {
			if (snd_queue.isEmpty())
				break;
			final KcpSeg newseg = snd_queue.next();
			newseg.unlink();
			newseg.linkTail(snd_buf);
			newseg.cmd = IKCP_CMD_PUSH;
			newseg.wnd = seg.wnd;
			newseg.ts = current;
			newseg.sn = snd_nxt++;
			newseg.una = rcv_nxt;
			newseg.resendts = current;
			newseg.rto = rx_rto;
			newseg.fastack = 0;
			newseg.xmit = 0;
			nsnd_que--;
			nsnd_buf++;
		}

		// flush data segments
		final int resent = fastresend;
		final int rtomin = nodelay == 0 ? rx_rto >>> 3 : 0;
		boolean change = false, lost = false;
		for (KcpSeg p = snd_buf.next(); p != snd_buf; p = p.next()) {
			boolean needsend = false;
			if (p.xmit == 0) {
				needsend = true;
				p.xmit++;
				p.rto = rx_rto;
				p.resendts = current + p.rto + rtomin;
			} else if (current - p.resendts >= 0) {
				needsend = true;
				p.xmit++;
				if (nodelay == 0)
					p.rto += Math.max(p.rto, rx_rto);
				else
					p.rto += (nodelay < 2 ? p.rto : rx_rto) / 2;
				p.resendts = current + p.rto;
				lost = true;
			} else if (p.fastack >= resent && p.xmit <= IKCP_FASTACK_LIMIT) {
				needsend = true;
				p.xmit++;
				p.fastack = 0;
				p.resendts = current + p.rto;
				change = true;
			}
			if (needsend) {
				p.ts = current;
				p.wnd = seg.wnd;
				p.una = rcv_nxt;
				if (pos + p.len > mss) {
					output0(pos);
					pos = 0;
				}
				encode_seg(pos, p);
				pos += IKCP_OVERHEAD;
				if (p.len > 0) {
					System.arraycopy(p.data, 0, buffer, pos, p.len);
					pos += p.len;
				}
			}
		}

		// flush remain segments
		if (pos > 0)
			output0(pos);

		// update ssthresh
		if (lost) {
			ssthresh = cwnd / 2;
			if (ssthresh < IKCP_THRESH_MIN)
				ssthresh = IKCP_THRESH_MIN;
			this.cwnd = 1;
			incr = mss;
		} else if (change) {
			ssthresh = (snd_nxt - snd_una) / 2;
			if (ssthresh < IKCP_THRESH_MIN)
				ssthresh = IKCP_THRESH_MIN;
			this.cwnd = ssthresh + resent;
			incr = this.cwnd * mss;
		}
		if (this.cwnd < 1) {
			this.cwnd = 1;
			incr = mss;
		}
	}

	private void update_ack(final int rtt) { // only for input
		if (rx_srtt == 0) {
			rx_rttval = rtt / 2;
			rx_srtt = rtt;
		} else {
			rx_rttval = (rx_rttval * 3 + Math.abs(rtt - rx_srtt)) / 4;
			rx_srtt = Math.max((rx_srtt * 7 + rtt) / 8, 1);
		}
		final int rto = rx_srtt + Math.max(interval, rx_rttval * 4);
		rx_rto = Math.min(Math.max(rx_minrto, rto), IKCP_RTO_MAX);
	}

	private void shrink_buf() { // only for input
		final KcpSeg p = snd_buf.next();
		snd_una = p != snd_buf ? p.sn : snd_nxt;
	}

	private void parse_ack(final int sn) { // uint32_t, only for input
		if (sn - snd_una < 0 || sn - snd_nxt >= 0)
			return;
		for (KcpSeg p = snd_buf.next(); p != snd_buf && sn - p.sn >= 0; p = p.next()) {
			if (sn == p.sn) {
				p.unlink();
				freeSeg(p);
				nsnd_buf--;
				break;
			}
		}
	}

	private void parse_una(final int una) { // uint32_t, only for input
		for (KcpSeg p = snd_buf.next(); p != snd_buf && una - p.sn > 0; ) {
			final KcpSeg next = p.next();
			p.unlink();
			freeSeg(p);
			p = next;
			nsnd_buf--;
		}
	}

	private void parse_fastack(final int sn, final int ts) { // uint32_t, only for input
		if (sn - snd_una < 0 || sn - snd_nxt >= 0)
			return;
		for (KcpSeg p = snd_buf.next(); p != snd_buf && sn - p.sn >= 0; p = p.next())
			if (sn != p.sn && (!IKCP_FASTACK_CONSERVE || ts - p.ts >= 0))
				p.fastack++;
	}

	private void ack_push(final int sn, final int ts) { // uint32_t, only for input
		final int newsize = ackcount + 1;
		if (newsize * 2 > acklist.length) {
			int newblock = 16;
			while (newblock < newsize)
				newblock <<= 1;
			acklist = Arrays.copyOf(acklist, newblock * 2);
		}
		acklist[ackcount * 2] = sn;
		acklist[ackcount * 2 + 1] = ts;
		ackcount = newsize;
	}

	private void parse_data(final KcpSeg newseg) { // only for input
		final int sn = newseg.sn;
		if (sn - (rcv_nxt + rcv_wnd) >= 0 || sn - rcv_nxt < 0) {
			freeSeg(newseg);
			return;
		}

		boolean repeat = false;
		KcpSeg p = rcv_buf.prev();
		for (; p != rcv_buf && sn - p.sn <= 0; p = p.prev()) {
			if (p.sn == sn) {
				repeat = true;
				break;
			}
		}
		if (repeat)
			freeSeg(newseg);
		else
			newseg.linkNext(p);

		// move available data from rcv_buf -> rcv_queue
		while (!rcv_buf.isEmpty()) {
			final KcpSeg seg = rcv_buf.next();
			if (seg.sn != rcv_nxt || nrcv_que >= rcv_wnd)
				break;
			seg.unlink();
			seg.linkTail(rcv_queue);
			nrcv_que++;
			rcv_nxt++;
		}
	}

	/**
	 * when you received a low level packet (eg. UDP packet), call it
	 */
	public final int input(final byte[] buf, int pos, int len) {
		if (canlog(IKCP_LOG_INPUT))
			log("[RI] %d bytes", len);
		if (buf == null || len < IKCP_OVERHEAD)
			return -1;

		int prev_una = snd_una, maxack = 0, latest_ts = 0;
		boolean flag = false;
		while (len >= IKCP_OVERHEAD) {
			if (decode32u(buf, pos) != conv)
				return -2;
			final int cmd = decode8u(buf, pos + 4);
			final int frg = decode8u(buf, pos + 5);
			final int wnd = decode16u(buf, pos + 6);
			final int ts = decode32u(buf, pos + 8);
			final int sn = decode32u(buf, pos + 12);
			final int una = decode32u(buf, pos + 16);
			final int size = decode32u(buf, pos + 20);
			pos += IKCP_OVERHEAD;
			len -= IKCP_OVERHEAD;
			if (len < size || size < 0)
				return -3;
			if (cmd != IKCP_CMD_PUSH && cmd != IKCP_CMD_ACK && cmd != IKCP_CMD_WASK && cmd != IKCP_CMD_WINS)
				return -4;

			rmt_wnd = wnd;
			parse_una(una);
			shrink_buf();
			if (cmd == IKCP_CMD_ACK) {
				if (current - ts >= 0)
					update_ack(current - ts);
				parse_ack(sn);
				shrink_buf();
				if (!flag) {
					flag = true;
					maxack = sn;
					latest_ts = ts;
				} else if (sn - maxack > 0 && (!IKCP_FASTACK_CONSERVE || ts - latest_ts > 0)) {
					maxack = sn;
					latest_ts = ts;
				}
				if (canlog(IKCP_LOG_IN_ACK))
					log("input ack: sn=%d rtt=%d rto=%d", sn, current - ts, rx_rto);
			} else if (cmd == IKCP_CMD_PUSH) {
				if (canlog(IKCP_LOG_IN_DATA))
					log("input psh: sn=%d ts=%d", sn, ts);
				if (sn - (rcv_nxt + rcv_wnd) < 0) {
					ack_push(sn, ts);
					if (sn - rcv_nxt >= 0) {
						final KcpSeg seg = allocSeg(size);
						seg.cmd = (byte)cmd;
						seg.frg = (byte)frg;
						seg.wnd = (short)wnd;
						seg.ts = ts;
						seg.sn = sn;
						seg.una = una;
						seg.len = size;
						if (size > 0)
							System.arraycopy(buf, pos, seg.data, 0, size);
						parse_data(seg);
					}
				}
			} else if (cmd == IKCP_CMD_WASK) {
				probe |= IKCP_ASK_TELL; // ready to send back IKCP_CMD_WINS in 'flush', tell remote my window size
				if (canlog(IKCP_LOG_IN_PROBE))
					log("input probe");
			} else if (canlog(IKCP_LOG_IN_WINS))
				log("input wins: %d", wnd);
			pos += size;
			len -= size;
		}
		if (flag)
			parse_fastack(maxack, latest_ts);
		if (snd_una - prev_una > 0) {
			if (cwnd < rmt_wnd) {
				final int mss = this.mss;
				if (cwnd < ssthresh) {
					cwnd++;
					incr += mss;
				} else {
					if (incr < mss)
						incr = mss;
					incr += mss * mss / incr + mss / 16;
					if ((cwnd + 1) * mss <= incr)
						cwnd = (incr + mss - 1) / mss;
				}
				if (cwnd > rmt_wnd) {
					cwnd = rmt_wnd;
					incr = rmt_wnd * mss;
				}
			}
		}
		return 0;
	}

	/**
	 * check the size of next message in the recv queue
	 */
	public final int peeksize() { // const, rcv_queue=>size
		if (rcv_queue.isEmpty())
			return -1;
		KcpSeg p = rcv_queue.next();
		if (p.frg == 0)
			return p.len;
		if (nrcv_que < (p.frg & 0xff) + 1)
			return -2;
		for (int len = 0; p != rcv_queue; p = p.next()) {
			len += p.len;
			if (p.frg == 0)
				return len;
		}
		return -3;
	}

	/**
	 * user/upper level recv: returns size, returns below zero for EAGAIN
	 */
	public final int recv(final byte[] buf, int pos, int len) { // rcv_queue=>buf, rcv_buf=>rcv_queue
		final int peeksize = peeksize();
		if (peeksize < 0)
			return peeksize;
		final boolean ispeek = len < 0;
		if (ispeek)
			len = -len;
		if (peeksize > len)
			return -4;

		// merge fragment
		final boolean recover = nrcv_que >= rcv_wnd;
		len = 0;
		for (KcpSeg p = rcv_queue.next(); p != rcv_queue; ) {
			if (buf != null) {
				System.arraycopy(p.data, 0, buf, pos, p.len);
				pos += p.len;
			}
			len += p.len;
			if (canlog(IKCP_LOG_RECV))
				log("recv sn=%d", p.sn);
			final byte frg = p.frg;
			final KcpSeg next = p.next();
			if (!ispeek) {
				p.unlink();
				freeSeg(p);
				nrcv_que--;
			}
			p = next;
			if (frg == 0)
				break;
		}

		// move available data from rcv_buf -> rcv_queue
		while (!rcv_buf.isEmpty()) {
			final KcpSeg seg = rcv_buf.next();
			if (seg.sn != rcv_nxt || nrcv_que >= rcv_wnd)
				break;
			seg.unlink();
			seg.linkTail(rcv_queue);
			nrcv_que++;
			rcv_nxt++;
		}

		// fast recover
		if (nrcv_que < rcv_wnd && recover)
			probe |= IKCP_ASK_TELL; // ready to send back IKCP_CMD_WINS in 'flush', tell remote my window size
		return len;
	}

	/**
	 * Determine when should you invoke 'update':
	 * returns when you should invoke 'update' in millisec, if there is no 'input/send' calling.
	 * you can call 'update' in that time, instead of call 'update' repeatly.
	 * Important to reduce unnacessary 'update' invoking.
	 * use it to schedule 'update' (eg. implementing an epoll-like mechanism,
	 * or optimize 'update' when handling massive kcp connections)
	 */
	public final int check(final int current) // const
	{
		final int tm_flush = ts_flush - current;
		if (tm_flush <= 0 || tm_flush > 10000)
			return current;
		int tm_packet = Integer.MAX_VALUE;
		for (KcpSeg p = snd_buf.next(); p != snd_buf; p = p.next()) {
			final int diff = p.resendts - current;
			if (diff <= 0)
				return current;
			if (tm_packet > diff)
				tm_packet = diff;
		}
		return current + Math.min(Math.min(tm_packet, tm_flush), interval);
	}

	/**
	 * update state (call it repeatedly, every 10ms-100ms),
	 * or you can ask 'check' when to call it again (without 'input/send' calling).
	 * 'current' - current timestamp in millisec.
	 */
	public final void update(final int current) {
		final int slap = current - ts_flush;
		if (slap < -10000 || slap >= interval)
			ts_flush = current + interval;
		else if (slap >= 0)
			ts_flush += interval;
		else {
			this.current = current;
			return;
		}
		flush(current);
	}
}
