package org.apache.sshd.client;

import java.net.SocketAddress;

import org.apache.sshd.ClientSession;

public interface ServerKeyVerifier {
    boolean verifyServerKey(ClientSession sshClientSession, SocketAddress remoteAddress, byte[] serverKey);
}
