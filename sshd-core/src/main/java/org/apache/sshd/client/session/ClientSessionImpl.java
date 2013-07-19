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
package org.apache.sshd.client.session;

import java.io.IOException;
import java.net.SocketAddress;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.mina.core.session.IoSession;
import org.apache.sshd.ClientChannel;
import org.apache.sshd.ClientSession;
import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.ServerKeyVerifier;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.client.UserInteraction;
import org.apache.sshd.client.auth.UserAuthAgent;
import org.apache.sshd.client.auth.UserAuthKeyboardInteractive;
import org.apache.sshd.client.auth.UserAuthPassword;
import org.apache.sshd.client.auth.UserAuthPublicKey;
import org.apache.sshd.client.channel.ChannelDirectTcpip;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.channel.ChannelSubsystem;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.DefaultAuthFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Channel;
import org.apache.sshd.common.KeyExchange;
import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.SshdSocketAddress;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.channel.OpenChannelException;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientSessionImpl extends AbstractSession implements ClientSession {

    private static final String AUTHENTICATION_SERVICE = "ssh-connection";

    private UserAuth userAuth;
    /**
     * The AuthFuture that is being used by the current auth request.  This encodes the state.
     * isSuccess -> authenticated, else if isDone -> server waiting for user auth, else authenticating.
     */
    private volatile AuthFuture authFuture;

    /**
     * For clients to store their own metadata
     */
    private Map<Object, Object> metadataMap = new HashMap<Object, Object>();

    public ClientSessionImpl(ClientFactoryManager client, IoSession session) throws Exception {
        super(client, session);
        log.info("Session created...");
        sendClientIdentification();
        sendKexInit();
        // Maintain the current auth status in the authFuture.
        authFuture = new DefaultAuthFuture(lock);
    }

    public ClientFactoryManager getClientFactoryManager() {
        return (ClientFactoryManager) factoryManager;
    }

    public KeyExchange getKex() {
        return kex;
    }

    /**
     * return true if/when ready for auth; false if never ready.
     * @return server is ready and waiting for auth
     */
    private boolean readyForAuth() {
        // isDone indicates that the last auth finished and a new one can commence.
        while (!this.authFuture.isDone()) {
            log.debug("waiting to send authentication");
            try {
                this.authFuture.await();
            } catch (InterruptedException e) {
                log.debug("Unexpected interrupt", e);
                throw new RuntimeException(e);
            }
        }
        if (this.authFuture.isSuccess()) {
            log.debug("already authenticated");
            throw new IllegalStateException("Already authenticated");
        }
        if (this.authFuture.getException() != null) {
            log.debug("probably closed", this.authFuture.getException());
            return false;
        }
        if (!this.authFuture.isFailure()) {
            log.debug("unexpected state");
            throw new IllegalStateException("Unexpected authentication state");
        }
        if (this.userAuth != null) {
            log.debug("authentication already in progress");
            throw new IllegalStateException("Authentication already in progress?");
        }
        log.debug("ready to try authentication with new lock");
        // The new future !isDone() - i.e., in progress blocking out other waits.
        this.authFuture = new DefaultAuthFuture(lock);
        return true;
    }

    /**
     * execute one step in user authentication.
     * @param buffer
     * @throws IOException
     */
    private void processUserAuth(Buffer buffer) throws IOException {
        log.debug("processing {}", userAuth);
        switch (userAuth.next(buffer)) {
            case Success:
                log.debug("succeeded with {}", userAuth);
                this.authed = true;
                this.username = userAuth.getUsername();
                setState(State.Running);
                // Will wake up anyone sitting in waitFor
                authFuture.setAuthed(true);
                startHeartBeat();
                break;
            case Failure:
                log.debug("failed with {}", userAuth);
                this.userAuth = null;
                setState(State.WaitForAuth);
                // Will wake up anyone sitting in waitFor
                this.authFuture.setAuthed(false);
                break;
            case Continued:
                // Will wake up anyone sitting in waitFor
                setState(State.UserAuth);
                log.debug("continuing with {}", userAuth);
                break;
        }
    }

    public AuthFuture authAgent(String user) throws IOException {
        log.debug("Trying agent authentication");
        if (getFactoryManager().getAgentFactory() == null) {
            throw new IllegalStateException("No ssh agent factory has been configured");
        }
        synchronized (lock) {
            if (readyForAuth()) {
                userAuth = new UserAuthAgent(this, AUTHENTICATION_SERVICE, user);
                processUserAuth(null);
            }
            return authFuture;
        }
    }

    public AuthFuture authPassword(String user, String password) throws IOException {
        log.debug("Trying password authentication");
        synchronized (lock) {
            if (readyForAuth()) {
                userAuth = new UserAuthPassword(this, AUTHENTICATION_SERVICE, user, password);
                processUserAuth(null);
            }
            return authFuture;
        }
    }

    public AuthFuture authInteractive(String user, String password) throws IOException {
        log.debug("Trying keyboard-interactive authentication");
        synchronized (lock) {
            if (readyForAuth()) {
                userAuth = new UserAuthKeyboardInteractive(this, AUTHENTICATION_SERVICE, user, password);
                processUserAuth(null);
            }
            return authFuture;
        }
   }

    public AuthFuture authPublicKey(String user, KeyPair key) throws IOException {
        log.debug("Trying publickey authentication");
        synchronized (lock) {
            if (readyForAuth()) {
                userAuth = new UserAuthPublicKey(this, AUTHENTICATION_SERVICE, user, key);
                processUserAuth(null);
            }
            return authFuture;
        }
    }

    public ClientChannel createChannel(String type) throws Exception {
        return createChannel(type, null);
    }

    public ClientChannel createChannel(String type, String subType) throws Exception {
        if (ClientChannel.CHANNEL_SHELL.equals(type)) {
            return createShellChannel();
        } else if (ClientChannel.CHANNEL_EXEC.equals(type)) {
            return createExecChannel(subType);
        } else if (ClientChannel.CHANNEL_SUBSYSTEM.equals(type)) {
            return createSubsystemChannel(subType);
        } else {
            throw new IllegalArgumentException("Unsupported channel type " + type);
        }
    }

    public ChannelShell createShellChannel() throws Exception {
        ChannelShell channel = new ChannelShell();
        registerChannel(channel);
        return channel;
    }

    public ChannelExec createExecChannel(String command) throws Exception {
        ChannelExec channel = new ChannelExec(command);
        registerChannel(channel);
        return channel;
    }

    public ChannelSubsystem createSubsystemChannel(String subsystem) throws Exception {
        ChannelSubsystem channel = new ChannelSubsystem(subsystem);
        registerChannel(channel);
        return channel;
    }

    public ChannelDirectTcpip createDirectTcpipChannel(SshdSocketAddress local, SshdSocketAddress remote) throws Exception {
        ChannelDirectTcpip channel = new ChannelDirectTcpip(local, remote);
        registerChannel(channel);
        return channel;
    }

    public SshdSocketAddress startLocalPortForwarding(SshdSocketAddress local, SshdSocketAddress remote) throws Exception {
        return getTcpipForwarder().startLocalPortForwarding(local, remote);
    }

    public void stopLocalPortForwarding(SshdSocketAddress local) throws Exception {
        getTcpipForwarder().stopLocalPortForwarding(local);
    }

    public SshdSocketAddress startRemotePortForwarding(SshdSocketAddress remote, SshdSocketAddress local) throws Exception {
        return getTcpipForwarder().startRemotePortForwarding(remote, local);
    }

    public void stopRemotePortForwarding(SshdSocketAddress remote) throws Exception {
        getTcpipForwarder().stopRemotePortForwarding(remote);
    }

    @Override
    public CloseFuture close(boolean immediately) {
        synchronized (lock) {
            if (!authFuture.isDone()) {
                authFuture.setException(new SshException("Session is closed"));
            }
            return super.close(immediately);
        }
    }

    protected void handleMessage(Buffer buffer) throws Exception {
        synchronized (lock) {
            doHandleMessage(buffer);
        }
    }

    protected void doHandleMessage(Buffer buffer) throws Exception {
        SshConstants.Message cmd = buffer.getCommand();
        log.debug("Received packet {}", cmd);
        switch (cmd) {
            case SSH_MSG_DISCONNECT: {
                int code = buffer.getInt();
                String msg = buffer.getString();
                log.info("Received SSH_MSG_DISCONNECT (reason={}, msg={})", code, msg);
                close(false);
                break;
            }
            case SSH_MSG_UNIMPLEMENTED: {
                int code = buffer.getInt();
                log.info("Received SSH_MSG_UNIMPLEMENTED #{}", code);
                break;
            }
            case SSH_MSG_DEBUG: {
                boolean display = buffer.getBoolean();
                String msg = buffer.getString();
                log.info("Received SSH_MSG_DEBUG (display={}) '{}'", display, msg);
                break;
            }
            case SSH_MSG_IGNORE:
                log.info("Received SSH_MSG_IGNORE");
                break;
            default:
                switch (getState()) {
                    case ReceiveKexInit:
                        if (cmd != SshConstants.Message.SSH_MSG_KEXINIT) {
                            log.error("Ignoring command " + cmd + " while waiting for " + SshConstants.Message.SSH_MSG_KEXINIT);
                            break;
                        }
                        log.info("Received SSH_MSG_KEXINIT");
                        receiveKexInit(buffer);
                        negociate();
                        kex = NamedFactory.Utils.create(factoryManager.getKeyExchangeFactories(), negociated[SshConstants.PROPOSAL_KEX_ALGS]);
                        kex.init(this, serverVersion.getBytes(), clientVersion.getBytes(), I_S, I_C);
                        setState(State.Kex);
                        break;
                    case Kex:
                        buffer.rpos(buffer.rpos() - 1);
                        if (kex.next(buffer)) {
                            checkHost();
                            sendNewKeys();
                            setState(State.ReceiveNewKeys);
                        }
                        break;
                    case ReceiveNewKeys:
                        if (cmd != SshConstants.Message.SSH_MSG_NEWKEYS) {
                            disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Protocol error: expected packet SSH_MSG_NEWKEYS, got " + cmd);
                            return;
                        }
                        log.info("Received SSH_MSG_NEWKEYS");
                        receiveNewKeys(false);
                        sendAuthRequest();
                        setState(State.AuthRequestSent);
                        break;
                    case AuthRequestSent:
                        if (cmd != SshConstants.Message.SSH_MSG_SERVICE_ACCEPT) {
                            disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Protocol error: expected packet SSH_MSG_SERVICE_ACCEPT, got " + cmd);
                            return;
                        }
                        authFuture.setAuthed(false);
                        setState(State.WaitForAuth);
                        break;
                    case WaitForAuth:
                        // We're waiting for the client to send an authentication request
                        // TODO: handle unexpected incoming packets
                        break;
                    case UserAuth:
                        if (userAuth == null) {
                            throw new IllegalStateException("State is userAuth, but no user auth pending!!!");
                        }
                        if (cmd == SshConstants.Message.SSH_MSG_USERAUTH_BANNER) {
                            String welcome = buffer.getString();
                            String lang = buffer.getString();
                            log.debug("Welcome banner: " + welcome);
                            UserInteraction ui = getClientFactoryManager().getUserInteraction();
                            if (ui != null) {
                                ui.welcome(welcome);
                            }
                        } else {
                            buffer.rpos(buffer.rpos() - 1);
                            processUserAuth(buffer);
                        }
                        break;
                    case Running:
                        switch (cmd) {
                            case SSH_MSG_REQUEST_SUCCESS:
                                requestSuccess(buffer);
                                break;
                            case SSH_MSG_REQUEST_FAILURE:
                                requestFailure(buffer);
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
                            case SSH_MSG_CHANNEL_FAILURE:
                                channelFailure(buffer);
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
                            default:
                                throw new IllegalStateException("Unsupported command: " + cmd);
                        }
                        break;
                    default:
                        throw new IllegalStateException("Unsupported state: " + getState());
                }
        }
    }

    public int waitFor(int mask, long timeout) {
        long t = 0;
        synchronized (lock) {
            for (;;) {
                int cond = 0;
                if (closeFuture.isClosed()) {
                    cond |= CLOSED;
                }
                if (authed) { // authFuture.isSuccess()
                    cond |= AUTHED;
                }
                if (authFuture.isFailure()) {
                    cond |= WAIT_AUTH;
                }
                if ((cond & mask) != 0) {
                    return cond;
                }
                if (timeout > 0) {
                    if (t == 0) {
                        t = System.currentTimeMillis() + timeout;
                    } else {
                        timeout = t - System.currentTimeMillis();
                        if (timeout <= 0) {
                            cond |= TIMEOUT;
                            return cond;
                        }
                    }
                }
                try {
                    if (timeout > 0) {
                        lock.wait(timeout);
                    } else {
                        lock.wait();
                    }
                } catch (InterruptedException e) {
                    // Ignore
                }
            }
        }
    }

    public void setState(State newState) {
        synchronized (lock) {
            super.setState(newState);
            lock.notifyAll();
        }
    }

    protected void startHeartBeat() {
        String intervalStr = getClientFactoryManager().getProperties().get(ClientFactoryManager.HEARTBEAT_INTERVAL);
        try {
            int interval = intervalStr != null ? Integer.parseInt(intervalStr) : 0;
            if (interval > 0) {
                getClientFactoryManager().getScheduledExecutorService().scheduleAtFixedRate(new Runnable() {
                    public void run() {
                        sendHeartBeat();
                    }
                }, interval, interval, TimeUnit.MILLISECONDS);
            }
        } catch (NumberFormatException e) {
            log.warn("Ignoring bad heartbeat interval: {}", intervalStr);
        }
    }

    protected void sendHeartBeat() {
        try {
            Buffer buf = createBuffer(SshConstants.Message.SSH_MSG_GLOBAL_REQUEST, 0);
            String request = getClientFactoryManager().getProperties().get(ClientFactoryManager.HEARTBEAT_REQUEST);
            if (request == null) {
                request = "keepalive@sshd.apache.org";
            }
            buf.putString(request);
            buf.putBoolean(false);
            writePacket(buf);
        } catch (IOException e) {
            log.info("Error sending keepalive message", e);
        }
    }

    protected boolean readIdentification(Buffer buffer) throws IOException {
        serverVersion = doReadIdentification(buffer);
        if (serverVersion == null) {
            return false;
        }
        log.info("Server version string: {}", serverVersion);
        if (!(serverVersion.startsWith("SSH-2.0-") || serverVersion.startsWith("SSH-1.99-"))) {
            throw new SshException(SshConstants.SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED,
                                   "Unsupported protocol version: " + serverVersion);
        }
        return true;
    }

    private void sendClientIdentification() {
        clientVersion = "SSH-2.0-" + getFactoryManager().getVersion();
        sendIdentification(clientVersion);
    }

    private void sendKexInit() throws Exception {
        clientProposal = createProposal(KeyPairProvider.SSH_RSA + "," + KeyPairProvider.SSH_DSS);
        I_C = sendKexInit(clientProposal);
    }

    private void receiveKexInit(Buffer buffer) throws Exception {
        serverProposal = new String[SshConstants.PROPOSAL_MAX];
        I_S = receiveKexInit(buffer, serverProposal);
    }

    private void checkHost() throws SshException {
        ServerKeyVerifier serverKeyVerifier = getClientFactoryManager().getServerKeyVerifier();
        SocketAddress remoteAddress = ioSession.getRemoteAddress();

        if (!serverKeyVerifier.verifyServerKey(this, remoteAddress, kex.getServerKey())) {
            throw new SshException("Server key did not validate");
        }
    }

    private void sendAuthRequest() throws Exception {
        log.info("Send SSH_MSG_SERVICE_REQUEST for ssh-userauth");
        Buffer buffer = createBuffer(SshConstants.Message.SSH_MSG_SERVICE_REQUEST, 0);
        buffer.putString("ssh-userauth");
        writePacket(buffer);
    }

    private void channelOpen(Buffer buffer) throws Exception {
        String type = buffer.getString();
        final int id = buffer.getInt();
        final int rwsize = buffer.getInt();
        final int rmpsize = buffer.getInt();

        log.info("Received SSH_MSG_CHANNEL_OPEN {}", type);

        if (closing) {
            Buffer buf = createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_OPEN_FAILURE, 0);
            buf.putInt(id);
            buf.putInt(SshConstants.SSH_OPEN_CONNECT_FAILED);
            buf.putString("SSH server is shutting down: " + type);
            buf.putString("");
            writePacket(buf);
            return;
        }

        final Channel channel = NamedFactory.Utils.create(getFactoryManager().getChannelFactories(), type);
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
                            buf.putInt(((OpenChannelException)future.getException()).getReasonCode());
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

	public Map<Object, Object> getMetadataMap() {
		return metadataMap;
	}

}
