package org.apache.sshd.common.forward.sshd85;

import java.io.IOException;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ApacheServerApacheClient extends AbstractServerCloseTest {
	private static final Logger log = LoggerFactory.getLogger(ApacheServerApacheClient.class);

	private static final int CLIENT_TO_SERVER_CONNECT_TIMEOUT = 10_000;

	private static final int SSH_SERVER_PORT = 1123;

	private static SshServer server;
	private ClientSession session;

	/**
	 * Starts an SSH Server
	 */
	@BeforeClass
	public static void startSshServer() throws IOException {
		log.info("Starting SSHD...");

		// System.setProperty(IoServiceFactory.class.getName(),
		// MinaServiceFactory.class.getName());

		server = SshServer.setUpDefaultServer();
		server.setPasswordAuthenticator((u, p, s) -> true);
		server.setTcpipForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
		server.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
		server.setPort(SSH_SERVER_PORT);
		server.start();
		log.info("SSHD Running on port {}", server.getPort());
	}

	@AfterClass
	public static void stopServer() throws IOException {
		server.close(true).await();
	}

	@Before
	public void createClient() throws IOException {
		log.info("Creating SSH Client...");
		final SshClient client = SshClient.setUpDefaultClient();
		client.setTcpipForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
		log.info("Starting");
		client.start();
		log.info("Connecting...");
		session = client.connect("user", "localhost", SSH_SERVER_PORT).verify(CLIENT_TO_SERVER_CONNECT_TIMEOUT)
				.getSession();
		log.info("Connected");
		session.addPasswordIdentity("foo");
		session.auth().verify(CLIENT_TO_SERVER_CONNECT_TIMEOUT);
		log.info("SSH Client connected to server.");
	}

	@After
	public void stopClient() throws Exception {
		log.info("Disconnecting Client");
		session.close(true).await(CLIENT_TO_SERVER_CONNECT_TIMEOUT);
	}

	@Override
	protected int startRemotePF() throws Exception {
		final SshdSocketAddress remote = new SshdSocketAddress("localhost", 0);
		final SshdSocketAddress local = new SshdSocketAddress("localhost", TEST_SERVER_PORT);
		final SshdSocketAddress bound = session.startRemotePortForwarding(remote, local);
		return bound.getPort();
	}

	@Override
	protected int startLocalPF() throws Exception {
		final SshdSocketAddress remote = new SshdSocketAddress("localhost", 0);
		final SshdSocketAddress local = new SshdSocketAddress("localhost", TEST_SERVER_PORT);
		final SshdSocketAddress bound = session.startLocalPortForwarding(remote, local);
		return bound.getPort();
	}

}
