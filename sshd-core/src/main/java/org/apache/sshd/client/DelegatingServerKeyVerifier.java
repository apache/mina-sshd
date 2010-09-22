package org.apache.sshd.client;

import java.net.SocketAddress;
import java.util.Map;

import org.apache.sshd.ClientSession;
import org.apache.sshd.common.util.BufferUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/*
 * A ServerKeyVerifier that delegates verification to the ServerKeyVerifier found in the ClientSession metadata
 * The ServerKeyVerifier can be specified at the SshClient level, which may have connections to multiple hosts.
 * This technique lets each connection have its own ServerKeyVerifier.
 */
public class DelegatingServerKeyVerifier implements ServerKeyVerifier {
	protected final Logger log = LoggerFactory.getLogger(getClass());

	public boolean verifyServerKey(ClientSession sshClientSession, SocketAddress remoteAddress, byte[] serverKey) {
		Map<Object, Object> metadataMap = sshClientSession.getMetadataMap();
		Object verifier = metadataMap.get(ServerKeyVerifier.class);
		if (verifier == null) {
			log.trace("No verifier found in ClientSession metadata; accepting server key");
			return true;
		}
		// We throw if it's not a ServerKeyVerifier...
		return ((ServerKeyVerifier) verifier).verifyServerKey(sshClientSession, remoteAddress, serverKey);
	}
}
