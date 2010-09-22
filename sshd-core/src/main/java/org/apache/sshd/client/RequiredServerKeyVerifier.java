package org.apache.sshd.client;

import java.net.SocketAddress;
import java.util.Arrays;

import org.apache.sshd.ClientSession;
import org.apache.sshd.common.util.BufferUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A ServerKeyVerifier that accepts one server key (specified in the constructor)
 *
 */
public class RequiredServerKeyVerifier implements ServerKeyVerifier {
	protected final Logger log = LoggerFactory.getLogger(getClass());
	final byte[] requiredKey;

	public RequiredServerKeyVerifier(byte[] requiredKey) {
		super();
		this.requiredKey = requiredKey;
	}

	public boolean verifyServerKey(ClientSession sshClientSession, SocketAddress remoteAddress, byte[] serverKey) {
		if (Arrays.equals(requiredKey, serverKey)) {
			return true;
		}

		log.info("Server at " + remoteAddress + " presented wrong key: " + BufferUtils.printHex(serverKey));
		return false;
	}
}
