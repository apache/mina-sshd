/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.server.session;

import java.io.IOException;
import java.security.KeyPair;

import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.ServerFactoryManager;

/**
 *
 * TODO: handle key re-exchange
 *          key re-exchange should be performed after each gigabyte of transferred data
 *          or one hour time connection (see RFC4253, section 9)
 *
 * TODO: better use of SSH_MSG_DISCONNECT and disconnect error codes
 *
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ServerSession extends AbstractSession {

    private long authTimeoutTimestamp;
    private long idleTimeoutTimestamp = 0L;
    private int authTimeoutMs = 2 * 60 * 1000; // 2 minutes in milliseconds
    private int idleTimeoutMs = 10 * 60 * 1000; // 10 minutes in milliseconds

    public ServerSession(ServerFactoryManager server, IoSession ioSession) throws Exception {
        super(true, server, ioSession);
        authTimeoutMs = getIntProperty(ServerFactoryManager.AUTH_TIMEOUT, authTimeoutMs);
        authTimeoutTimestamp = System.currentTimeMillis() + authTimeoutMs;
        idleTimeoutMs = getIntProperty(ServerFactoryManager.IDLE_TIMEOUT, idleTimeoutMs);
        log.info("Session created from {}", ioSession.getRemoteAddress());
        sendServerIdentification();
        kexState = KEX_STATE_INIT;
        sendKexInit();
    }

    public String getNegotiated(int index) {
        return negotiated[index];
    }

    public ServerFactoryManager getFactoryManager() {
        return (ServerFactoryManager) factoryManager;
    }

    protected void checkKeys() {
    }

    public void startService(String name) throws Exception {
        currentService = ServiceFactory.Utils.create(getFactoryManager().getServiceFactories(), name, this);
    }

    @Override
    protected void serviceAccept() throws IOException {
        // TODO: can services be initiated by the server-side ?
        disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Unsupported packet: SSH_MSG_SERVICE_ACCEPT");
    }

    /**
     * Checks whether the server session has timed out (both auth and idle timeouts are checked). If the session has
     * timed out, a DISCONNECT message will be sent to the client.
     *
     * @throws IOException
     */
    protected void checkForTimeouts() throws IOException {
        if (!closing) {
            long now = System.currentTimeMillis();
            if (!authed && now > authTimeoutTimestamp) {
                disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Session has timed out waiting for authentication after " + authTimeoutMs + " ms.");
            }
            if (idleTimeoutTimestamp > 0 && now > idleTimeoutTimestamp) {
                disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "User session has timed out idling after " + idleTimeoutMs + " ms.");
            }
        }
    }

    public void resetIdleTimeout() {
        this.idleTimeoutTimestamp = System.currentTimeMillis() + idleTimeoutMs;
    }

    private void sendServerIdentification() {
        if (getFactoryManager().getProperties() != null && getFactoryManager().getProperties().get(ServerFactoryManager.SERVER_IDENTIFICATION) != null) {
            serverVersion = "SSH-2.0-" + getFactoryManager().getProperties().get(ServerFactoryManager.SERVER_IDENTIFICATION);
        } else {
            serverVersion = "SSH-2.0-" + getFactoryManager().getVersion();
        }
        sendIdentification(serverVersion);
    }

    protected void sendKexInit() throws IOException {
        serverProposal = createProposal(factoryManager.getKeyPairProvider().getKeyTypes());
        I_S = sendKexInit(serverProposal);
    }

    protected boolean readIdentification(Buffer buffer) throws IOException {
        clientVersion = doReadIdentification(buffer);
        if (clientVersion == null) {
            return false;
        }
        log.debug("Client version string: {}", clientVersion);
        if (!clientVersion.startsWith("SSH-2.0-")) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED,
                                   "Unsupported protocol version: " + clientVersion);
        }
        return true;
    }

    protected void receiveKexInit(Buffer buffer) throws IOException {
        clientProposal = new String[SshConstants.PROPOSAL_MAX];
        I_C = receiveKexInit(buffer, clientProposal);
    }

    public KeyPair getHostKey() {
        return factoryManager.getKeyPairProvider().loadKey(negotiated[SshConstants.PROPOSAL_SERVER_HOST_KEY_ALGS]);
    }

    /**
     * Retrieve the current number of sessions active for a given username.
     * @param userName The name of the user
     * @return The current number of live <code>SshSession</code> objects associated with the user
     */
    protected int getActiveSessionCountForUser(String userName) {
        int totalCount = 0;
        for (IoSession is : ioSession.getService().getManagedSessions().values()) {
            ServerSession session = (ServerSession) getSession(is, true);
            if (session != null) {
                if (session.getUsername() != null && session.getUsername().equals(userName)) {
                    totalCount++;
                }
            }
        }
        return totalCount;
    }

	/**
	 * Returns the session id.
	 * 
	 * @return The session id.
	 */
	public long getId() {
		return ioSession.getId();
	}
}
