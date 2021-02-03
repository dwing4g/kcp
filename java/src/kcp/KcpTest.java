package kcp;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Random;

final class DelayPacket {
	final byte[] buf;
	final int len;
	int ts;

	DelayPacket(byte[] buf, int len) {
		this.buf = Arrays.copyOf(buf, len);
		this.len = len;
	}

	byte[] buf() {
		return buf;
	}

	int len() {
		return len;
	}

	int ts() {
		return ts;
	}

	void setts(int ts) {
		this.ts = ts;
	}
}

final class Rand {
	private static final boolean FIXED_RANDOM = true;
	private static final Random random = FIXED_RANDOM ? null : new Random();
	private static int seed;

	static int nextInt(int n) {
		if (!FIXED_RANDOM)
			return random.nextInt(n);
		seed = (seed * 987654321 + 123456789) & 0x7fffffff;
		return seed % n;
	}

	final int[] seeds;
	int size;

	Rand(int size) {
		seeds = new int[size];
	}

	int random() {
		if (seeds.length == 0)
			return 0;
		if (size <= 0) {
			for (int i = 0; i < seeds.length; i++)
				seeds[i] = i;
			size = seeds.length;
		}
		int i = nextInt(size);
		int x = seeds[i];
		seeds[i] = seeds[--size];
		return x;
	}
}

final class Timer {
	private static final boolean FIXED_TIME = true;
	int current;

	int iclock() {
		return FIXED_TIME ? current : (int)(System.nanoTime() / 1000000);
	}

	void sleep(@SuppressWarnings("SameParameterValue") int ms) throws InterruptedException {
		if (FIXED_TIME)
			current += ms;
		else
			Thread.sleep(ms);
	}
}

final class LatencySimulator {
	final Timer timer = new Timer();
	int tx1;
	int tx2;
	int current = timer.iclock();
	final int lostrate;
	final int rttmin;
	final int rttmax;
	static final int nmax = 1000;
	final LinkedList<DelayPacket> p12 = new LinkedList<DelayPacket>();
	final LinkedList<DelayPacket> p21 = new LinkedList<DelayPacket>();
	final Rand r12 = new Rand(100);
	final Rand r21 = new Rand(100);

	// lostrate: 往返一周丢包率的百分比，默认 10%
	// rttmin：rtt最小值，默认 60
	// rttmax：rtt最大值，默认 125
	LatencySimulator(int lostrate, int rttmin, int rttmax) {
		this.lostrate = lostrate / 2; // 上面数据是往返丢包率，单程除以2
		this.rttmin = rttmin / 2;
		this.rttmax = rttmax / 2;
	}

	Timer getTimer() {
		return timer;
	}

	// peer - 端点0/1，从0发送，从1接收；从1发送从0接收
	void send(int peer, byte[] buf, int len) {
		if (peer == 0) {
			tx1++;
			if (r12.random() < lostrate || p12.size() >= nmax)
				return;
		} else {
			tx2++;
			if (r21.random() < lostrate || p21.size() >= nmax)
				return;
		}
		DelayPacket pkt = new DelayPacket(buf, len);
		current = timer.iclock();
		int delay = rttmin;
		if (rttmax > rttmin)
			delay += Rand.nextInt(rttmax - rttmin);
		pkt.setts(current + delay);
		(peer == 0 ? p12 : p21).addLast(pkt);
	}

	int recv(int peer, byte[] buf, @SuppressWarnings("SameParameterValue") int maxsize) {
		Iterator<DelayPacket> it;
		if (peer == 0) {
			if (p21.isEmpty())
				return -1;
			it = p21.iterator();
		} else {
			if (p12.isEmpty())
				return -1;
			it = p12.iterator();
		}
		DelayPacket pkt = it.next();
		current = timer.iclock();
		if (current < pkt.ts())
			return -2;
		if (maxsize < pkt.len())
			return -3;
		it.remove();
		maxsize = pkt.len();
		System.arraycopy(pkt.buf(), 0, buf, 0, maxsize);
		return maxsize;
	}
}

public final class KcpTest extends Kcp {
	private static final boolean VERBOSE = false;
	private final LatencySimulator vnet;
	private final int id;

	private KcpTest(LatencySimulator vnet, int id, int conv, int current) {
		super(conv, current, false);
		this.vnet = vnet;
		this.id = id;
	}

	// 设置kcp的下层输出，这里为 udp_output，模拟udp网络输出函数
	@Override
	public void output(byte[] buf, int len) {
		vnet.send(id, buf, len);
	}

	private static int segMentSize(Segment head) {
		int n = 0;
		for (Segment p = head.next; p != head; p = p.next)
			n++;
		return n;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(); // ("KcpTest(id=").append(id).append(")\n");
		try {
			for (Field field : Kcp.class.getDeclaredFields()) {
				if ((field.getModifiers() & Modifier.STATIC) != 0)
					continue;
				final String fieldName = field.getName();
				if (fieldName.equals("acklist") || fieldName.equals("buffer"))
					continue;
				field.setAccessible(true);
				sb.append(fieldName).append(": ");
				final Class<?> type = field.getType();
				if (type == int.class)
					sb.append(field.getInt(this));
				else if (type == byte.class)
					sb.append(field.getByte(this));
				else if (type == boolean.class)
					sb.append(field.getBoolean(this) ? 1 : 0);
				else if (type == Segment.class && field.get(this) != null)
					sb.append('[').append(segMentSize((Segment)field.get(this))).append(']');
				else if (type == int[].class && field.get(this) != null)
					sb.append('[').append(((int[])field.get(this)).length).append(']');
				else if (type == byte[].class && field.get(this) != null)
					sb.append('[').append(((byte[])field.get(this)).length).append(']');
				sb.append('\n');
			}
		} catch (IllegalAccessException e) {
			e.printStackTrace();
		}
		return sb.toString();
	}

	private static void test(int mode) throws Exception {
		// 创建模拟网络：丢包率10%，Rtt 60ms~125ms
		LatencySimulator vnet = new LatencySimulator(10, 60, 125);
		int current = vnet.getTimer().iclock();

		// 创建两个端点的 kcp对象，第一个参数 conv是会话编号，同一个会话需要相同
		// 最后一个是 user参数，用来传递标识
		KcpTest kcp1 = new KcpTest(vnet, 0, 0x11223344, current);
		KcpTest kcp2 = new KcpTest(vnet, 1, 0x11223344, current);
		if (VERBOSE) {
			kcp1.logmask(-1);
			kcp2.logmask(-1);
		}

		int slap = current + 20;
		int index = 0;
		int next = 0;
		long sumrtt = 0;
		int count = 0;
		int maxrtt = 0;

		// 配置窗口大小：平均延迟200ms，每20ms发送一个包，
		// 而考虑到丢包重发，设置最大收发窗口为128
		kcp1.wndsize(128, 128);
		kcp2.wndsize(128, 128);

		// 判断测试用例的模式
		if (mode == 0) {
			// 默认模式
			kcp1.nodelay(0, 10, 0, 0);
			kcp2.nodelay(0, 10, 0, 0);
		} else if (mode == 1) {
			// 普通模式，关闭流控等
			kcp1.nodelay(0, 10, 0, 1);
			kcp2.nodelay(0, 10, 0, 1);
		} else {
			// 启动快速模式
			// 第二个参数 nodelay-启用以后若干常规加速将启动
			// 第三个参数 interval为内部处理时钟，默认设置为 10ms
			// 第四个参数 resend为快速重传指标，设置为2
			// 第五个参数 为是否禁用常规流控，这里禁止
			kcp1.nodelay(2, 10, 2, 1);
			kcp2.nodelay(2, 10, 2, 1);
			kcp1.rx_minrto(10);
			kcp1.fastresend(1);
		}

		byte[] buf = new byte[2000];
		int ts1 = vnet.getTimer().iclock();
		do {
			vnet.getTimer().sleep(1);
			current = vnet.getTimer().iclock();
			kcp1.update(current);
			kcp2.update(current);

			// 每隔 20ms，kcp1发送数据
			for (; current >= slap; slap += 20) {
				encode32u(buf, 0, index++);
				encode32u(buf, 4, current);
				// 发送上层协议包
				kcp1.send(buf, 0, 8);
			}

			// 处理虚拟网络：检测是否有udp包从p1->p2
			for (; ; ) {
				int hr = vnet.recv(1, buf, 2000);
				if (hr < 0)
					break;
				// 如果 p2收到udp，则作为下层协议输入到kcp2
				kcp2.input(buf, 0, hr);
			}

			// 处理虚拟网络：检测是否有udp包从p2->p1
			for (; ; ) {
				int hr = vnet.recv(0, buf, 2000);
				if (hr < 0)
					break;
				// 如果 p1收到udp，则作为下层协议输入到kcp1
				kcp1.input(buf, 0, hr);
			}

			// kcp2接收到任何包都返回回去
			for (; ; ) {
				int hr = kcp2.recv(buf, 0, 10);
				// 没有收到包就退出
				if (hr < 0)
					break;
				// 如果收到包就回射
				kcp2.send(buf, 0, hr);
			}

			// kcp1收到kcp2的回射数据
			for (; ; ) {
				int hr = kcp1.recv(buf, 0, 10);
				// 没有收到包就退出
				if (hr < 0)
					break;
				int sn = decode32u(buf, 0);
				int ts = decode32u(buf, 4);
				int rtt = current - ts;

				if (sn != next) {
					// 如果收到的包不连续
					System.out.printf("ERROR sn(%d) %d<->%d\n", sn, count, next);
					return;
				}

				next++;
				sumrtt += rtt;
				count++;
				if (rtt > maxrtt)
					maxrtt = rtt;

				System.out.printf("[RECV] mode=%d sn=%d rtt=%d\n", mode, sn, rtt);
			}
			if (VERBOSE) {
				System.out.printf("------ current: %d\n", current);
				System.out.print(kcp1.toString());
				System.out.print("------\n");
				System.out.print(kcp2.toString());
				System.out.print("------\n");
			}
		} while (next <= 1000);

		ts1 = vnet.getTimer().iclock() - ts1;
		String[] names = {"default", "normal", "fast"};
		System.out.printf("%s mode result (%dms):\n", names[mode], ts1);
		System.out.printf("avgrtt=%d maxrtt=%d tx=%d\n", (int)(sumrtt / count), maxrtt, vnet.tx1);

//		System.out.print("press enter to next ...\n");
//		//noinspection ResultOfMethodCallIgnored
//		System.in.read();
	}

	public static void main(String[] args) throws Exception {
		test(0); // 默认模式，类似 TCP：正常模式，无快速重传，常规流控
		test(1); // 普通模式，关闭流控等
		test(2); // 快速模式，所有开关都打开，且关闭流控
	}
}
