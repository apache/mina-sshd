package org.apache.sshd.common.forward.sshd85;

public class NoServerNoClient extends AbstractServerCloseTest {

	@Override
	protected int startRemotePF() throws Exception {
		return TEST_SERVER_PORT;
	}

	@Override
	protected int startLocalPF() throws Exception {
		return TEST_SERVER_PORT;
	}

}
