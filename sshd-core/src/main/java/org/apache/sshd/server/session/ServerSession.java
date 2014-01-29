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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;

import org.apache.sshd.SshServer;
import org.apache.sshd.agent.common.AgentForwardSupport;
import org.apache.sshd.agent.local.ChannelAgentForwarding;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Channel;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.SshdSocketAddress;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.channel.OpenChannelException;
import org.apache.sshd.server.x11.X11ForwardSupport;

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
        super(server, ioSession);
        authTimeoutMs = getIntProperty(ServerFactoryManager.AUTH_TIMEOUT, authTimeoutMs);
        authTimeoutTimestamp = System.currentTimeMillis() + authTimeoutMs;
        idleTimeoutMs = getIntProperty(ServerFactoryManager.IDLE_TIMEOUT, idleTimeoutMs);
        log.info("Session created from {}", ioSession.getRemoteAddress());
        sendServerIdentification();
        sendKexInit();
    }

    public String getNegociated(int index) {
        return negociated[index];
    }

    public ServerFactoryManager getServerFactoryManager() {
        return (ServerFactoryManager) factoryManager;
    }

    protected ScheduledExecutorService getScheduledExecutorService() {
        return getServerFactoryManager().getScheduledExecutorService();
    }

    @Override
    public IoWriteFuture writePacket(Buffer buffer) throws IOException {
        boolean rescheduleIdleTimer = getState() == State.Running;
        if (rescheduleIdleTimer) {
            resetIdleTimeout();
        }
        IoWriteFuture future = super.writePacket(buffer);
        if (rescheduleIdleTimer) {
            resetIdleTimeout();
        }
        return future;
    }

    protected void handleMessage(Buffer buffer) throws Exception {
        SshConstants.Message cmd = buffer.getCommand();
        log.debug("Received packet {}", cmd);
        switch (cmd) {
            case SSH_MSG_DISCONNECT: {
                int code = buffer.getInt();
                String msg = buffer.getString();
                log.debug("Received SSH_MSG_DISCONNECT (reason={}, msg={})", code, msg);
                close(true);
                break;
            }
            case SSH_MSG_UNIMPLEMENTED: {
                int code = buffer.getInt();
                log.debug("Received SSH_MSG_UNIMPLEMENTED #{}", code);
                break;
            }
            case SSH_MSG_DEBUG: {
                boolean display = buffer.getBoolean();
                String msg = buffer.getString();
                log.debug("Received SSH_MSG_DEBUG (display={}) '{}'", display, msg);
                break;
            }
            case SSH_MSG_IGNORE:
                log.debug("Received SSH_MSG_IGNORE");
                break;
            default:
                switch (getState()) {
                    case ReceiveKexInit:
                        if (cmd != SshConstants.Message.SSH_MSG_KEXINIT) {
                            log.warn("Ignoring command " + cmd + " while waiting for " + SshConstants.Message.SSH_MSG_KEXINIT);
                            break;
                        }
                        log.debug("Received SSH_MSG_KEXINIT");
                        receiveKexInit(buffer);
                        negociate();
                        kex = NamedFactory.Utils.create(factoryManager.getKeyExchangeFactories(), negociated[SshConstants.PROPOSAL_KEX_ALGS]);
                        kex.init(this, serverVersion.getBytes(), clientVersion.getBytes(), I_S, I_C);
                        setState(State.Kex);
                        break;
                    case Kex:
                        buffer.rpos(buffer.rpos() - 1);
                        if (kex.next(buffer)) {
                            sendNewKeys();
                            setState(State.ReceiveNewKeys);
                        }
                        break;
                    case ReceiveNewKeys:
                        if (cmd != SshConstants.Message.SSH_MSG_NEWKEYS) {
                            disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Protocol error: expected packet " + SshConstants.Message.SSH_MSG_NEWKEYS + ", got " + cmd);
                            return;
                        }
                        log.debug("Received SSH_MSG_NEWKEYS");
                        receiveNewKeys(true);
                        setState(State.WaitForServiceRequest);
                        break;
                    case WaitForServiceRequest:
                        if (cmd != SshConstants.Message.SSH_MSG_SERVICE_REQUEST) {
                            log.debug("Expecting a {}, but received {}", SshConstants.Message.SSH_MSG_SERVICE_REQUEST, cmd);
                            notImplemented();
                        } else {
                            String service = buffer.getString();
                            log.debug("Received SSH_MSG_SERVICE_REQUEST '{}'", service);
                            try {
                                startService(service);
                            } catch (Exception e) {
                                log.debug("Service " + service + " rejected", e);
                                disconnect(SshConstants.SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, "Bad service request: " + service);
                                break;
                            }
                            log.debug("Accepted service {}", service);
                            Buffer response = createBuffer(SshConstants.Message.SSH_MSG_SERVICE_ACCEPT, 0);
                            response.putString(service);
                            writePacket(response);
                            setState(State.Running);
                        }
                        break;
                    case Running:
                        running(cmd, buffer);
                        resetIdleTimeout();
                        break;
                    default:
                        throw new IllegalStateException("Unsupported state: " + getState());
                }
        }
    }

    public void startService(String name) throws Exception {
        currentService = ServiceFactory.Utils.create(getFactoryManager().getServiceFactories(), name, this);
    }

    private void running(SshConstants.Message cmd, Buffer buffer) throws Exception {
        switch (cmd) {
            case SSH_MSG_KEXINIT:
                receiveKexInit(buffer);
                sendKexInit();
                negociate();
                kex = NamedFactory.Utils.create(factoryManager.getKeyExchangeFactories(), negociated[SshConstants.PROPOSAL_KEX_ALGS]);
                kex.init(this, serverVersion.getBytes(), clientVersion.getBytes(), I_S, I_C);
                break;
            case SSH_MSG_KEXDH_INIT:
                buffer.rpos(buffer.rpos() - 1);
                if (kex.next(buffer)) {
                    sendNewKeys();
                }
                break;
            case SSH_MSG_NEWKEYS:
                receiveNewKeys(true);
                break;
            default:
                currentService.process(cmd, buffer);
                break;
        }
    }

    /**
     * Checks whether the server session has timed out (both auth and idle timeouts are checked). If the session has
     * timed out, a DISCONNECT message will be sent to the client.
     *
     * @throws IOException
     */
    protected void checkForTimeouts() throws IOException {
        if (getState() != State.Closed) {
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

    private void sendKexInit() throws IOException {
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

    private void receiveKexInit(Buffer buffer) throws IOException {
        clientProposal = new String[SshConstants.PROPOSAL_MAX];
        I_C = receiveKexInit(buffer, clientProposal);
    }

    public KeyPair getHostKey() {
        return factoryManager.getKeyPairProvider().loadKey(negociated[SshConstants.PROPOSAL_SERVER_HOST_KEY_ALGS]);
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
