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
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.SshServer;
import org.apache.sshd.agent.common.AgentForwardSupport;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Channel;
import org.apache.sshd.common.KeyExchange;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.SshdSocketAddress;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.io.IoSession;
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

    private Future authTimerFuture;
    private Future idleTimerFuture;
    private int maxAuthRequests = 20;
    private int nbAuthRequests;
    private int authTimeout = 10 * 60 * 1000; // 10 minutes in milliseconds
    private int idleTimeout = 10 * 60 * 1000; // 10 minutes in milliseconds
    private boolean allowMoreSessions = true;
    private final AgentForwardSupport agentForward;
    private final X11ForwardSupport x11Forward;

    private List<NamedFactory<UserAuth>> userAuthFactories;
    private List<List<String>> authMethods;
    private String authUserName;
    private String authMethod;
    private String authService;
    private UserAuth currentAuth;

    public ServerSession(ServerFactoryManager server, IoSession ioSession) throws Exception {
        super(server, ioSession);
        maxAuthRequests = getIntProperty(ServerFactoryManager.MAX_AUTH_REQUESTS, maxAuthRequests);
        authTimeout = getIntProperty(ServerFactoryManager.AUTH_TIMEOUT, authTimeout);
        idleTimeout = getIntProperty(ServerFactoryManager.IDLE_TIMEOUT, idleTimeout);
        agentForward = new AgentForwardSupport(this);
        x11Forward = new X11ForwardSupport(this);
        log.info("Session created from {}", ioSession.getRemoteAddress());
        sendServerIdentification();
        sendKexInit();
    }

    @Override
    public CloseFuture close(boolean immediately) {
        unscheduleAuthTimer();
        unscheduleIdleTimer();
        agentForward.close();
        x11Forward.close();
        return super.close(immediately);
    }

    public String getNegociated(int index) {
        return negociated[index];
    }

    public KeyExchange getKex() {
        return kex;
    }

    public byte [] getSessionId() {
      return sessionId;
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
            unscheduleIdleTimer();
        }
        IoWriteFuture future = super.writePacket(buffer);
        if (rescheduleIdleTimer) {
            scheduleIdleTimer();
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
                        setState(State.WaitForAuth);
                        scheduleAuthTimer();
                        break;
                    case WaitForAuth:
                        if (cmd != SshConstants.Message.SSH_MSG_SERVICE_REQUEST) {
                            log.debug("Expecting a {}, but received {}", SshConstants.Message.SSH_MSG_SERVICE_REQUEST, cmd);
                            notImplemented();
                        } else {
                            String request = buffer.getString();
                            log.debug("Received SSH_MSG_SERVICE_REQUEST '{}'", request);
                            if ("ssh-userauth".equals(request)) {
                                userAuth(buffer, null);
                            } else {
                                disconnect(SshConstants.SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, "Bad service request: " + request);
                            }
                        }
                        break;
                    case UserAuth:
                        if (cmd != SshConstants.Message.SSH_MSG_USERAUTH_REQUEST && currentAuth == null) {
                            disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Protocol error: expected packet " + SshConstants.Message.SSH_MSG_USERAUTH_REQUEST + ", got " + cmd);
                            return;
                        }
                        log.debug("Received " + cmd);
                        userAuth(buffer, cmd);
                        break;
                    case Running:
                        unscheduleIdleTimer();
                        running(cmd, buffer);
                        scheduleIdleTimer();
                        break;
                    default:
                        throw new IllegalStateException("Unsupported state: " + getState());
                }
        }
    }

    private void running(SshConstants.Message cmd, Buffer buffer) throws Exception {
        switch (cmd) {
            case SSH_MSG_SERVICE_REQUEST:
                serviceRequest(buffer);
                break;
            case SSH_MSG_CHANNEL_OPEN:
                channelOpen(buffer);
                break;
            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                channelOpenConfirmation(buffer);
                break;
            case SSH_MSG_CHANNEL_OPEN_FAILURE:
                channelOpenFailure(buffer);
                break;
            case SSH_MSG_CHANNEL_REQUEST:
                channelRequest(buffer);
                break;
            case SSH_MSG_CHANNEL_DATA:
                channelData(buffer);
                break;
            case SSH_MSG_CHANNEL_EXTENDED_DATA:
                channelExtendedData(buffer);
                break;
            case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                channelWindowAdjust(buffer);
                break;
            case SSH_MSG_CHANNEL_EOF:
                channelEof(buffer);
                break;
            case SSH_MSG_CHANNEL_CLOSE:
                channelClose(buffer);
                break;
            case SSH_MSG_GLOBAL_REQUEST:
                globalRequest(buffer);
                break;
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
                throw new IllegalStateException("Unsupported command: " + cmd);
        }
    }

    private void scheduleAuthTimer() {
        Runnable authTimerTask = new Runnable() {
            public void run() {
                try {
                    processAuthTimer();
                } catch (IOException e) {
                    // Ignore
                }
            }
        };
        authTimerFuture = getScheduledExecutorService().schedule(authTimerTask, authTimeout, TimeUnit.MILLISECONDS);
    }

    private void unscheduleAuthTimer() {
        if (authTimerFuture != null) {
            authTimerFuture.cancel(false);
            authTimerFuture = null;
        }
    }

    private void scheduleIdleTimer() {
        if (idleTimeout < 1) {
            // A timeout less than one means there is no timeout.
            return;
        }
        synchronized (this) {
            unscheduleIdleTimer();
            Runnable idleTimerTask = new Runnable() {
                public void run() {
                    try {
                        processIdleTimer();
                    } catch (IOException e) {
                        // Ignore
                    }
                }
            };
            idleTimerFuture = getScheduledExecutorService().schedule(idleTimerTask, idleTimeout, TimeUnit.MILLISECONDS);
        }
    }

    private void unscheduleIdleTimer() {
        synchronized (this) {
            if (idleTimerFuture != null) {
                idleTimerFuture.cancel(false);
                idleTimerFuture = null;
            }
        }
    }

    private void processAuthTimer() throws IOException {
        if (!authed) {
            disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                       "User authentication has timed out");
        }
    }

    private void processIdleTimer() throws IOException {
        disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "User session has timed out after being idled for " + idleTimeout + "ms.");
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

    private void serviceRequest(Buffer buffer) throws Exception {
        String request = buffer.getString();
        log.debug("Received SSH_MSG_SERVICE_REQUEST '{}'", request);
        // TODO: handle service requests
        disconnect(SshConstants.SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, "Unsupported service request: " + request);
    }

    private void userAuth(Buffer buffer, SshConstants.Message cmd) throws Exception {
        if (getState() == State.WaitForAuth) {
            log.debug("Accepting user authentication request");
            buffer = createBuffer(SshConstants.Message.SSH_MSG_SERVICE_ACCEPT, 0);
            buffer.putString("ssh-userauth");
            writePacket(buffer);
            userAuthFactories = new ArrayList<NamedFactory<UserAuth>>(getServerFactoryManager().getUserAuthFactories());
            // Get authentication methods
            authMethods = new ArrayList<List<String>>();
            String mths = getServerFactoryManager().getProperties().get(SshServer.AUTH_METHODS);
            if (mths == null) {
                for (NamedFactory<UserAuth> uaf : getServerFactoryManager().getUserAuthFactories()) {
                    authMethods.add(new ArrayList<String>(Collections.singletonList(uaf.getName())));
                }
            } else {
                for (String mthl : mths.split("\\s")) {
                    authMethods.add(new ArrayList<String>(Arrays.asList(mthl.split(","))));
                }
            }
            // Verify all required methods are supported
            for (List<String> l : authMethods) {
                for (String m : l) {
                    if (NamedFactory.Utils.get(userAuthFactories, m) == null) {
                        throw new SshException("Configured method is not supported: " + m);
                    }
                }
            }
            log.debug("Authorized authentication methods: {}", NamedFactory.Utils.getNames(userAuthFactories));
            setState(State.UserAuth);

        } else {

            Boolean authed = Boolean.FALSE;

            if (cmd == SshConstants.Message.SSH_MSG_USERAUTH_REQUEST) {
                if (this.currentAuth != null) {
                    this.currentAuth.destroy();
                    this.currentAuth = null;
                }

                String username = buffer.getString();
                String service = buffer.getString();
                String method = buffer.getString();
                if (this.authUserName == null || this.authService == null) {
                    this.authUserName = username;
                    this.authService = service;
                } else if (!this.authUserName.equals(username) || !this.authService.equals(service)) {
                    disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                            "Change of username or service is not allowed (" + this.authUserName + ", " + this.authService + ") -> ("
                                + username + ", " + service + ")");
                    return;
                }
                this.authMethod = method;
                if (nbAuthRequests++ > maxAuthRequests) {
                    disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Too may authentication failures");
                    return;
                }

                log.debug("Authenticating user '{}' with service '{}' and method '{}'", new Object[] { username, service, method });
                NamedFactory<UserAuth> factory = NamedFactory.Utils.get(userAuthFactories, method);
                if (factory != null) {
                    currentAuth = factory.create();
                    try {
                        authed = currentAuth.auth(this, username, service, buffer);
                    } catch (Exception e) {
                        // Continue
                        log.debug("Authentication failed: {}", e.getMessage());
                    }
                }
            } else  {
                if (this.currentAuth == null) {
                    // This should not happen
                    throw new IllegalStateException();
                }
                buffer.rpos(buffer.rpos() - 1);
                try {
                    authed = currentAuth.next(buffer);
                } catch (Exception e) {
                    // Continue
                    log.debug("Authentication failed: {}", e.getMessage());
                }
            }

            if (authed == null) {
                // authentication is still ongoing
                log.debug("Authentication not finished");
            } else if (authed) {
                log.debug("Authentication succeeded");
                username = currentAuth.getUserName();

                boolean success = false;
                for (List<String> l : authMethods) {
                    if (!l.isEmpty() && l.get(0).equals(authMethod)) {
                        l.remove(0);
                        success |= l.isEmpty();
                    }
                }
                if (success) {
                    if (getFactoryManager().getProperties() != null) {
                        String maxSessionCountAsString = getFactoryManager().getProperties().get(ServerFactoryManager.MAX_CONCURRENT_SESSIONS);
                        if (maxSessionCountAsString != null) {
                            int maxSessionCount = Integer.parseInt(maxSessionCountAsString);
                            int currentSessionCount = getActiveSessionCountForUser(username);
                            if (currentSessionCount >= maxSessionCount) {
                                disconnect(SshConstants.SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, "Too many concurrent connections");
                                return;
                            }
                        }
                    }

                    String welcomeBanner = factoryManager.getProperties().get(ServerFactoryManager.WELCOME_BANNER);
                    if (welcomeBanner != null) {
                        buffer = createBuffer(SshConstants.Message.SSH_MSG_USERAUTH_BANNER, 0);
                        buffer.putString(welcomeBanner);
                        buffer.putString("en");
                        writePacket(buffer);
                    }

                    buffer = createBuffer(SshConstants.Message.SSH_MSG_USERAUTH_SUCCESS, 0);
                    writePacket(buffer);
                    this.authed = true;
                    unscheduleAuthTimer();
                    setState(State.Running);
                    scheduleIdleTimer();
                    log.info("Session {}@{} authenticated", getUsername(), getIoSession().getRemoteAddress());

                } else {
                    buffer = createBuffer(SshConstants.Message.SSH_MSG_USERAUTH_FAILURE, 0);
                    StringBuilder sb = new StringBuilder();
                    for (List<String> l : authMethods) {
                        if (!l.isEmpty()) {
                            if (sb.length() > 0) {
                                sb.append(",");
                            }
                            sb.append(l.get(0));
                        }
                    }
                    buffer.putString(sb.toString());
                    buffer.putByte((byte) 1);
                    writePacket(buffer);
                }

                currentAuth.destroy();
                currentAuth = null;
            } else {
                log.debug("Authentication failed");

                buffer = createBuffer(SshConstants.Message.SSH_MSG_USERAUTH_FAILURE, 0);
                StringBuilder sb = new StringBuilder();
                for (List<String> l : authMethods) {
                    if (!l.isEmpty()) {
                        String m = l.get(0);
                        if (!"none".equals(m)) {
                            if (sb.length() > 0) {
                                sb.append(",");
                            }
                            sb.append(l.get(0));
                        }
                    }
                }
                buffer.putString(sb.toString());
                buffer.putByte((byte) 0);
                writePacket(buffer);

                if (currentAuth != null) {
                    currentAuth.destroy();
                    currentAuth = null;
                }
            }
        }
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

    private void channelOpen(Buffer buffer) throws Exception {
        String type = buffer.getString();
        final int id = buffer.getInt();
        final int rwsize = buffer.getInt();
        final int rmpsize = buffer.getInt();

        log.debug("Received SSH_MSG_CHANNEL_OPEN {}", type);

        if (closing) {
            Buffer buf = createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_OPEN_FAILURE, 0);
            buf.putInt(id);
            buf.putInt(SshConstants.SSH_OPEN_CONNECT_FAILED);
            buf.putString("SSH server is shutting down: " + type);
            buf.putString("");
            writePacket(buf);
            return;
        }
        if (!allowMoreSessions) {
            Buffer buf = createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_OPEN_FAILURE, 0);
            buf.putInt(id);
            buf.putInt(SshConstants.SSH_OPEN_CONNECT_FAILED);
            buf.putString("additional sessions disabled");
            buf.putString("");
            writePacket(buf);
            return;
        }

        final Channel channel = NamedFactory.Utils.create(getServerFactoryManager().getChannelFactories(), type);
        if (channel == null) {
            Buffer buf = createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_OPEN_FAILURE, 0);
            buf.putInt(id);
            buf.putInt(SshConstants.SSH_OPEN_UNKNOWN_CHANNEL_TYPE);
            buf.putString("Unsupported channel type: " + type);
            buf.putString("");
            writePacket(buf);
            return;
        }

        final int channelId = getNextChannelId();
        channels.put(channelId, channel);
        channel.init(this, channelId);
        channel.open(id, rwsize, rmpsize, buffer).addListener(new SshFutureListener<OpenFuture>() {
            public void operationComplete(OpenFuture future) {
                try {
                    if (future.isOpened()) {
                        Buffer buf = createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_OPEN_CONFIRMATION, 0);
                        buf.putInt(id);
                        buf.putInt(channelId);
                        buf.putInt(channel.getLocalWindow().getSize());
                        buf.putInt(channel.getLocalWindow().getPacketSize());
                        writePacket(buf);
                    } else if (future.getException() != null) {
                        Buffer buf = createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_OPEN_FAILURE, 0);
                        buf.putInt(id);
                        if (future.getException() instanceof OpenChannelException) {
                            buf.putInt(((OpenChannelException) future.getException()).getReasonCode());
                            buf.putString(future.getException().getMessage());
                        } else {
                            buf.putInt(0);
                            buf.putString("Error opening channel: " + future.getException().getMessage());
                        }
                        buf.putString("");
                        writePacket(buf);
                    }
                } catch (IOException e) {
                    exceptionCaught(e);
                }
            }
        });
    }

    private void globalRequest(Buffer buffer) throws Exception {
        String req = buffer.getString();
        boolean wantReply = buffer.getBoolean();
        log.debug("Received global request {}", req);
        if (req.startsWith("keepalive@")) {
            // Relatively standard KeepAlive directive, just wants failure
        } else if (req.equals("no-more-sessions@openssh.com")) {
            allowMoreSessions = false;
        } else if (req.equals("tcpip-forward")) {
            String address = buffer.getString();
            int port = buffer.getInt();
            try {
                SshdSocketAddress bound = getTcpipForwarder().localPortForwardingRequested(new SshdSocketAddress(address, port));
                port = bound.getPort();
                if (wantReply){
                    buffer = createBuffer(SshConstants.Message.SSH_MSG_REQUEST_SUCCESS, 0);
                    buffer.putInt(port);
                    writePacket(buffer);
                }
            } catch (Exception e) {
                log.debug("Error starting tcpip forward", e);
                if (wantReply) {
                    buffer = createBuffer(SshConstants.Message.SSH_MSG_REQUEST_FAILURE, 0);
                    writePacket(buffer);
                }
            }
            return;
        } else if (req.equals("cancel-tcpip-forward")) {
            String address = buffer.getString();
            int port = buffer.getInt();
            getTcpipForwarder().localPortForwardingCancelled(new SshdSocketAddress(address, port));
            if (wantReply){
                buffer = createBuffer(SshConstants.Message.SSH_MSG_REQUEST_SUCCESS, 0);
                writePacket(buffer);
            }
            return;
        } else {
            log.debug("Received SSH_MSG_GLOBAL_REQUEST {}", req);
            log.warn("Unknown global request: {}", req);
        }
        if (wantReply) {
            buffer = createBuffer(SshConstants.Message.SSH_MSG_REQUEST_FAILURE, 0);
            writePacket(buffer);
        }
    }

    public String initAgentForward() throws IOException {
        return agentForward.initialize();
    }

    public String createX11Display(boolean singleConnection, String authenticationProtocol, String authenticationCookie, int screen) throws IOException {
        return x11Forward.createDisplay(singleConnection, authenticationProtocol, authenticationCookie, screen);
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
