package org.apache.sshd.client;

import java.net.SocketAddress;
import java.security.PublicKey;

import org.apache.sshd.ClientSession;

public interface ServerKeyVerifier {
    boolean verifyServerKey(ClientSession sshClientSession, SocketAddress remoteAddress, PublicKey serverKey);
}
