package kcp;

public final class KcpSeg {
	private KcpSeg prev;
	private KcpSeg next;
	byte cmd;
	byte frg;
	short wnd;
	int ts;
	int sn;
	int una;
	int len;
	int resendts;
	int rto;
	int fastack;
	int xmit;
	final byte[] data;

	KcpSeg() {
		prev = this;
		next = this;
		data = null;
	}

	public KcpSeg(int capacity) {
		data = new byte[capacity];
	}

	public int capacity() {
		assert data != null;
		return data.length;
	}

	boolean isEmpty() {
		return next == this;
	}

	KcpSeg next() {
		return next;
	}

	KcpSeg prev() {
		return prev;
	}

	void linkNext(final KcpSeg node) {
		prev = node;
		next = node.next;
		next.prev = this;
		node.next = this;
	}

	void linkTail(final KcpSeg head) {
		prev = head.prev;
		next = head;
		prev.next = this;
		head.prev = this;
	}

	void unlink() {
		prev.next = next;
		next.prev = prev;
	}
}
