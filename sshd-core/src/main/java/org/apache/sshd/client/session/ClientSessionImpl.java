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
import java.security.PublicKey;

import org.apache.mina.core.session.IoSession;
import org.apache.sshd.ClientChannel;
import org.apache.sshd.ClientSession;
import org.apache.sshd.SshClient;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.client.auth.UserAuthPassword;
import org.apache.sshd.client.channel.AbstractClientChannel;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.DefaultAuthFuture;
import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.util.Buffer;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ClientSessionImpl extends AbstractSession implements ClientSession {

    public static final String SESSION = ClientSessionImpl.class.getName();

    public enum State {
        ReceiveKexInit, Kex, ReceiveNewKeys, AuthRequestSent, WaitForAuth, UserAuth, Running, Unknown
    }

    private State state = State.ReceiveKexInit;
    private UserAuth userAuth;
    private AuthFuture authFuture;

    public ClientSessionImpl(SshClient client, IoSession session) throws Exception {
        super(client, session);
        log.info("Session created...");
        sendClientIdentification();
        sendKexInit();
    }

    public AuthFuture authPassword(String username, String password) throws IOException {
        synchronized (lock) {
            if (closeFuture.isClosed()) {
                throw new IllegalStateException("Session is closed");
            }
            if (authed) {
                throw new IllegalStateException("User authentication has already been performed");
            }
            if (userAuth != null) {
                throw new IllegalStateException("A user authentication request is already pending");
            }
            waitFor(CLOSED | WAIT_AUTH, 0);
            if (closeFuture.isClosed()) {
                throw new IllegalStateException("Session is closed");
            }
            authFuture = new DefaultAuthFuture(lock);
            userAuth = new UserAuthPassword(this, username, password);
            setState(ClientSessionImpl.State.UserAuth);
            return authFuture;
        }
    }

    public AuthFuture authPublicKey(String username, PublicKey key) throws IOException {
        synchronized (lock) {
            if (closeFuture.isClosed()) {
                throw new IllegalStateException("Session is closed");
            }
            if (authed) {
                throw new IllegalStateException("User authentication has already been performed");
            }
            if (userAuth != null) {
                throw new IllegalStateException("A user authentication request is already pending");
            }
            waitFor(CLOSED | WAIT_AUTH, 0);
            if (closeFuture.isClosed()) {
                throw new IllegalStateException("Session is closed");
            }
            //authFuture = new DefaultAuthFuture<ClientSession>(this, lock);
            // TODO: implement public key authentication method
            throw new UnsupportedOperationException("Not supported yet");
        }
    }

    public ClientChannel createChannel(String type) throws Exception {
        // TODO: use NamedFactory to create channel
        AbstractClientChannel channel;
        if (ClientChannel.CHANNEL_SHELL.equals(type)) {
            channel = new ChannelShell();
        } else if (ClientChannel.CHANNEL_EXEC.equals(type)) {
            channel = new ChannelExec();
        } else {
            throw new IllegalArgumentException("Unsupported channel type " + type);
        }
        int id = ++nextChannelId;
        channel.init(this, id);
        channels.put(id, channel);
        return channel;
    }

    @Override
    public CloseFuture close(boolean immediately) {
        synchronized (lock) {
            if (authFuture != null && !authFuture.isDone()) {
                authFuture.setException(new SshException("Session is closed"));
            }
            return super.close(immediately);
        }
    }

    protected void handleMessage(Buffer buffer) throws Exception {
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
                switch (state) {
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
                        buffer.rpos(buffer.rpos() - 1);
                        switch (userAuth.next(buffer)) {
                             case Success:
                                 authFuture.setAuthed(true);
                                 authed = true;
                                 setState(State.Running);
                                 break;
                             case Failure:
                                 authFuture.setAuthed(false);
                                 userAuth = null;
                                 setState(State.WaitForAuth);
                                 break;
                             case Continued:
                                 break;
                        }
                        break;
                    case Running:
                        switch (cmd) {
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
                            // TODO: handle other requests
                        }
                        break;
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
                if (authed) {
                    cond |= AUTHED;
                }
                if (state == State.WaitForAuth) {
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
            this.state = newState;
            lock.notifyAll();
        }
    }

    protected boolean readIdentification(Buffer buffer) throws IOException {
        serverVersion = doReadIdentification(buffer);
        if (serverVersion == null) {
            return false;
        }
        log.info("Server version string: {}", serverVersion);
        if (!serverVersion.startsWith("SSH-2.0-")) {
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

    private void checkHost() throws Exception {
        // TODO: check host fingerprint
    }

    private void sendAuthRequest() throws Exception {
        log.info("Send SSH_MSG_SERVICE_REQUEST for ssh-userauth");
        Buffer buffer = createBuffer(SshConstants.Message.SSH_MSG_SERVICE_REQUEST);
        buffer.putString("ssh-userauth");
        writePacket(buffer);
    }

    private void channelOpenConfirmation(Buffer buffer) throws IOException {
        AbstractClientChannel channel = (AbstractClientChannel) getChannel(buffer);
        log.info("Received SSH_MSG_CHANNEL_OPEN_CONFIRMATION on channel {}", channel.getId());
        int recipient = buffer.getInt();
        int rwsize = buffer.getInt();
        int rmpsize = buffer.getInt();
        channel.internalOpenSuccess(recipient, rwsize, rmpsize);
    }

    private void channelOpenFailure(Buffer buffer) throws IOException {
        AbstractClientChannel channel = (AbstractClientChannel) getChannel(buffer);
        log.info("Received SSH_MSG_CHANNEL_OPEN_FAILURE on channel {}", channel.getId());
        channels.remove(channel.getId());
        channel.internalOpenFailure(buffer);
    }


}
