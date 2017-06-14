package org.apache.sshd.common.forward.sshd85;

import java.io.IOException;

import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.util.test.SimpleUserInfo;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;

public class ApacheServerJSchClient extends AbstractServerCloseTest {
	private static final Logger log = LoggerFactory.getLogger(ApacheServerJSchClient.class);

	private static final int SSH_SERVER_PORT = 1123;

	private static SshServer server;
	private Session session;

	/**
	 * Starts an SSH Server
	 */
	@BeforeClass
	public static void startSshServer() throws IOException {
		log.info("Starting SSHD...");
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
	public void createClient() throws Exception {
		log.info("Creating SSH Client...");
		JSch client = new JSch();
		log.info("Creating SSH Session...");
		session = client.getSession("user", "localhost", SSH_SERVER_PORT);
		session.setUserInfo(new SimpleUserInfo("password"));
		log.trace("Connecting session...");
		session.connect();
		log.trace("Client is running now...");
	}

	@After
	public void stopClient() throws Exception {
		log.info("Disconnecting Client");
		session.disconnect();
	}

	private int port = 12356;

	@Override
	protected int startRemotePF() throws Exception {
		port++;
		session.setPortForwardingR("localhost", port, "localhost", TEST_SERVER_PORT);
		return port;
	}

	@Override
	protected int startLocalPF() throws Exception {
		port++;
		session.setPortForwardingL("localhost", port, "localhost", TEST_SERVER_PORT);
		return port;
	}

}
