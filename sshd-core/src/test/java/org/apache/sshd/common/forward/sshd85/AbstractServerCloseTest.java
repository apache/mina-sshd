package org.apache.sshd.common.forward.sshd85;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousServerSocketChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.Collections;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * This test creates a test server that outputs a known string to every client
 * that connects, and then closes the connection. This is a perfectly reasonable
 * thing to do, and roughly mimics an HTTP 1.0 connection with a "Connection:
 * close" header, indicating that the server will return the content and then
 * close the TCP connection to indicate that all data has been sent.
 *
 * This test implements TWO methods to connect to and read data from that
 * server.
 *
 * readInOneBuffer allocates a buffer large enough to contain the response and
 * issues one read call to the Socket's InputStream, and then asserts that the
 * response is equal to the expected payload.
 *
 * readInTwoBuffers allocates a buffer smaller than the payload, issues two read
 * calls to the Socket's InputStream, and then asserts that the response is
 * equal to the expected payload. There is a 50 ms pause between these two reads
 * because at the heart of SSHD-85 is a race condition, and this pause makes the
 * test fail every time. Bear in mind that read(), sleep(50), read() is still a
 * perfectly reasonable thing to do; imagine that the client is a very slow
 * computer.
 *
 * These two read methods are then each called three times:
 *
 * - via an SSHD local port forward to the test server.
 *
 * - via an SSHD remote port forward to the test server.
 *
 * - directly to the test server, as a control.
 *
 * All four of these should pass, but the port forward / two buffer combinations
 * fail.
 *
 * The direct two buffer combination works.
 *
 *
 * @author bkuker
 *
 */
public abstract class AbstractServerCloseTest {
	private static final Logger log = LoggerFactory.getLogger(AbstractServerCloseTest.class);
	protected static final int TEST_SERVER_PORT = 1124;
	private final String PAYLOAD;
	private AsynchronousServerSocketChannel testServerSock;

	public AbstractServerCloseTest() {
		PAYLOAD = String.join("", Collections.nCopies(200, "This is significantly longer Test Data."));
	}

	/**
	 * Start a server to forward to.
	 *
	 * This server sends PAYLOAD and then closes.
	 */
	@Before
	public void startTestServer() throws Exception {
		final InetSocketAddress sockAddr = new InetSocketAddress("localhost", TEST_SERVER_PORT);
		testServerSock = AsynchronousServerSocketChannel.open().bind(sockAddr);
		// Accept a connection
		testServerSock.accept(testServerSock,
				new CompletionHandler<AsynchronousSocketChannel, AsynchronousServerSocketChannel>() {
					@Override
					public void completed(final AsynchronousSocketChannel sockChannel,
							final AsynchronousServerSocketChannel serverSock) {
						// a connection is accepted, start to accept next
						// connection
						serverSock.accept(serverSock, this);
						final ByteBuffer buf = ByteBuffer.wrap(PAYLOAD.getBytes());
						// start to write payload to client
						sockChannel.write(buf, sockChannel,
								new CompletionHandler<Integer, AsynchronousSocketChannel>() {
									@Override
									public void completed(final Integer result,
											final AsynchronousSocketChannel channel) {
										// Write has been completed, close the
										// connection to the client
										try {
											channel.close();
										} catch (final IOException e) {
											System.out.println("Failed to close");
										}
									}

									@Override
									public void failed(final Throwable exc, final AsynchronousSocketChannel channel) {
										System.out.println("Fail to write message to client");
									}
								});
					}

					@Override
					public void failed(final Throwable exc, final AsynchronousServerSocketChannel serverSock) {
						System.out.println("fail to accept a connection");
					}
				});
	}

	@After
	public void stopTestServer() throws Exception {
		testServerSock.close();
	}

	private void readInLoop(final int serverPort) throws Exception {
		log.debug("Connecting to {}", serverPort);
		final StringBuilder sb = new StringBuilder();
		try (Socket s = new Socket("localhost", serverPort)) {
			s.setSoTimeout(300);
			final byte b[] = new byte[PAYLOAD.length() / 10];
			for (int read = 0; (read = s.getInputStream().read(b)) != -1;) {
				sb.append(new String(b, 0, read));
				Thread.sleep(25);
			}
		} catch (final IOException e) {
			Assert.assertEquals(PAYLOAD.length(), sb.toString().length());
			Assert.assertEquals(PAYLOAD, sb.toString());
		}
	}

	private void readInOneBuffer(final int serverPort) throws Exception {
		log.debug("Connecting to {}", serverPort);
		try (Socket s = new Socket("localhost", serverPort)) {
			s.setSoTimeout(300);
			final byte b1[] = new byte[PAYLOAD.length()];
			final int read1 = s.getInputStream().read(b1);
			log.info("Got {} bytes from the server: {}", read1, new String(b1, 0, read1));
			Assert.assertEquals(PAYLOAD, new String(b1, 0, read1));
		}
	}

	private void readInTwoBuffersWithPause(final int serverPort) throws Exception {
		log.debug("Connecting to {}...", serverPort);
		try (Socket s = new Socket("localhost", serverPort)) {
			s.setSoTimeout(300);
			final byte b1[] = new byte[PAYLOAD.length() / 2];
			final byte b2[] = new byte[PAYLOAD.length()];

			final int read1 = s.getInputStream().read(b1);
			log.info("Got {} bytes from the server: {}", read1, new String(b1, 0, read1));

			Thread.sleep(50);

			try {
				final int read2 = s.getInputStream().read(b2);
				log.info("Got {} bytes from the server: {}", read2, new String(b2, 0, read2));
				Assert.assertEquals(PAYLOAD, new String(b1, 0, read1) + new String(b2, 0, read2));
			} catch (final SocketException e) {
				log.error("Disconnected before all data read: ", e);
				Assert.fail("Caught error from socket durning second read" + e.getMessage());
			}
		}
	}

	protected abstract int startRemotePF() throws Exception;

	protected abstract int startLocalPF() throws Exception;

	/**
	 * Connect to test server via port forward and read real quick with one big
	 * buffer.
	 *
	 * PROVIDED AS TEST THAT HAS ALWAYS PASSED
	 */
	@Test
	public final void remotePortForwardOneBuffer() throws Exception {
		readInOneBuffer(startRemotePF());
	}

	/**
	 * Connect to test server via port forward and read real quick with one big
	 * buffer.
	 *
	 * THIS IS THE TEST OF SSHD-85
	 */
	@Test
	public final void remotePortForwardTwoBuffers() throws Exception {
		readInTwoBuffersWithPause(startRemotePF());
	}

	@Test
	public final void remotePortForwardLoop() throws Exception {
		readInLoop(startRemotePF());
	}

	@Test
	public final void localPortForwardOneBuffer() throws Exception {
		readInOneBuffer(startLocalPF());
	}

	/**
	 * Connect to test server via port forward and read with 2 buffers and a
	 * pause in between.
	 *
	 * THIS IS THE TEST OF SSHD-85
	 */
	@Test
	public void localPortForwardTwoBuffers() throws Exception {

		readInTwoBuffersWithPause(startLocalPF());
	}

	@Test
	public void localPortForwardLoop() throws Exception {

		readInLoop(startLocalPF());
	}

}
