package org.apache.sshd.client;

import java.net.SocketAddress;
import java.security.PublicKey;
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
	final PublicKey requiredKey;

	public RequiredServerKeyVerifier(PublicKey requiredKey) {
		super();
		this.requiredKey = requiredKey;
	}

	public boolean verifyServerKey(ClientSession sshClientSession, SocketAddress remoteAddress, PublicKey serverKey) {
		if (requiredKey.equals(serverKey)) {
			return true;
		}

		log.info("Server at " + remoteAddress + " presented wrong key: " + BufferUtils.printHex(serverKey.getEncoded()));
		return false;
	}
}
