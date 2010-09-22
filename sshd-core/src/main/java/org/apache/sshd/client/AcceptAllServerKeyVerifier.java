package org.apache.sshd.client;

import java.net.SocketAddress;
import java.security.PublicKey;

import org.apache.sshd.ClientSession;
import org.apache.sshd.common.util.BufferUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A ServerKeyVerifier that accepts all server keys.
 */
public class AcceptAllServerKeyVerifier implements ServerKeyVerifier {
	protected final Logger log = LoggerFactory.getLogger(getClass());

	public static final ServerKeyVerifier INSTANCE = new AcceptAllServerKeyVerifier();

	private AcceptAllServerKeyVerifier() {
	}

	public boolean verifyServerKey(ClientSession sshClientSession, SocketAddress remoteAddress, PublicKey serverKey) {
		log.trace("Accepting key for " + remoteAddress + " key=" + BufferUtils.printHex(serverKey.getEncoded()));
		return true;
	}
}
