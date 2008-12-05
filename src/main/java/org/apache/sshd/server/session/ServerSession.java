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

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.io.IOException;

import org.apache.sshd.SshServer;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.ServerChannel;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.KeyExchange;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.util.Buffer;
import org.apache.mina.common.IoSession;
import org.apache.mina.common.TransportType;
import org.apache.mina.transport.socket.nio.SocketSessionConfig;

/**
 *
 * TODO: handle key re-exchange
 *          key re-exchange should be performed after each gigabyte of transferred data
 *          or one hour time connection (see RFC4253, section 9)
 *
 * TODO: better use of SSH_MSG_DISCONNECT and disconnect error codes
 *
 * TODO: use a single Timer for on the server for all sessions
 *
 * TODO: save the identity of the user so that the shell can access it if needed
 *
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public class ServerSession extends AbstractSession {

    private Timer timer;
    private TimerTask authTimerTask;
    private State state = State.ReceiveKexInit;
    private String username;
    private int maxAuthRequests = 20;
    private int nbAuthRequests;
    private int authTimeout = 10 * 60 * 1000; // 10 minutes in milliseconds

    private List<NamedFactory<UserAuth>> userAuthFactories;

    private enum State {
        ReceiveKexInit, Kex, ReceiveNewKeys, WaitingUserAuth, UserAuth, Running, Unknown
    }

    public ServerSession(SshServer server, IoSession ioSession) throws Exception {
        super(server, ioSession);
        maxAuthRequests = getIntProperty(FactoryManager.MAX_AUTH_REQUESTS, maxAuthRequests);
        authTimeout = getIntProperty(FactoryManager.AUTH_TIMEOUT, authTimeout);
        log.info("Session created...");
        if (ioSession.getTransportType() == TransportType.SOCKET) {
            ((SocketSessionConfig) ioSession.getConfig() ).setReceiveBufferSize( 2048 );
        }
        sendServerIdentification();
        sendKexInit();
    }

    @Override
    public void close() {
        super.close();
        unscheduleAuthTimer();
    }

    public String getNegociated(int index) {
        return negociated[index];
    }

    public KeyExchange getKex() {
        return kex;
    }

    public ServerFactoryManager getServerFactoryManager() {
        return (ServerFactoryManager) factoryManager;
    }

    public String getUsername() {
        return username;
    }

    protected void handleMessage(Buffer buffer) throws Exception {
        SshConstants.Message cmd = buffer.getCommand();
        log.debug("Received packet {}", cmd);
        switch (cmd) {
            case SSH_MSG_DISCONNECT: {
                int code = buffer.getInt();
                String msg = buffer.getString();
                log.info("Received SSH_MSG_DISCONNECT (reason={}, msg={})", code, msg);
                close();
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
                log.info("Received SSH_MSG_DEBUG '{}'", msg);
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
                        state = State.Kex;
                        break;
                    case Kex:
                        buffer.rpos(buffer.rpos() - 1);
                        if (kex.next(buffer)) {
                            sendNewKeys();
                            state = State.ReceiveNewKeys;
                        }
                        break;
                    case ReceiveNewKeys:
                        if (cmd != SshConstants.Message.SSH_MSG_NEWKEYS) {
                            disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Protocol error: expected packet " + SshConstants.Message.SSH_MSG_NEWKEYS + ", got " + cmd);
                            return;
                        }
                        log.info("Received SSH_MSG_NEWKEYS");
                        receiveNewKeys(true);
                        state = State.WaitingUserAuth;
                        scheduleAuthTimer();
                        break;
                    case WaitingUserAuth:
                        if (cmd != SshConstants.Message.SSH_MSG_SERVICE_REQUEST) {
                            log.info("Expecting a {}, but received {}", SshConstants.Message.SSH_MSG_SERVICE_REQUEST, cmd);
                            notImplemented();
                        } else {
                            String request = buffer.getString();
                            log.info("Received SSH_MSG_SERVICE_REQUEST '{}'", request);
                            if ("ssh-userauth".equals(request)) {
                                userAuth(buffer);
                            } else {
                                disconnect(SshConstants.SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, "Bad service request: " + request);
                            }
                        }
                        break;
                    case UserAuth:
                        if (cmd != SshConstants.Message.SSH_MSG_USERAUTH_REQUEST) {
                            disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Protocol error: expected packet " + SshConstants.Message.SSH_MSG_USERAUTH_REQUEST + ", got " + cmd);
                            return;
                        }
                        log.info("Received SSH_MSG_USERAUTH_REQUEST");
                        userAuth(buffer);
                        break;
                    case Running:
                        switch (cmd) {
                            case SSH_MSG_SERVICE_REQUEST:
                                serviceRequest(buffer);
                                break;
                            case SSH_MSG_CHANNEL_OPEN:
                                channelOpen(buffer);
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
                            default:
                                throw new IllegalStateException("Unsupported command: " + cmd);
                        }
                        break;
                    default:
                        throw new IllegalStateException("Unsupported state: " + state);
                }
        }
    }

    private void scheduleAuthTimer() {
        authTimerTask = new TimerTask() {
            public void run() {
                try {
                    processAuthTimer();
                } catch (IOException e) {
                    // Ignore
                }
            }
        };
        timer = new Timer(true);
        timer.schedule(authTimerTask, authTimeout);
    }

    private void unscheduleAuthTimer() {
        if (authTimerTask != null) {
            authTimerTask.cancel();
            authTimerTask = null;
        }
        if (timer != null) {
            timer.cancel();
            timer = null;
        }
    }

    private void processAuthTimer() throws IOException {
        if (!closed && !authed) {
            disconnect(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                       "User authentication has timed out");
            close();
        }
    }

    private void sendServerIdentification() {
        serverVersion = "SSH-2.0-" + getFactoryManager().getVersion();
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
        log.info("Client version string: {}", clientVersion);
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
        log.info("Received SSH_MSG_SERVICE_REQUEST '{}'", request);
        // TODO: handle service requests
        disconnect(SshConstants.SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, "Unsupported service request: " + request);
    }

    private void userAuth(Buffer buffer) throws Exception {
        if (state == State.WaitingUserAuth) {
            log.info("Accepting user authentication request");
            buffer = createBuffer(SshConstants.Message.SSH_MSG_SERVICE_ACCEPT);
            buffer.putString("ssh-userauth");
            writePacket(buffer);
            userAuthFactories = new ArrayList<NamedFactory<UserAuth>>(getServerFactoryManager().getUserAuthFactories());
            log.info("Authorized authentication methods: {}", NamedFactory.Utils.getNames(userAuthFactories));
            state = State.UserAuth;
        } else {
            if (nbAuthRequests++ > maxAuthRequests) {
                throw new SshException(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Too may authentication failures");
            }
            String username = buffer.getString();
            String svcName = buffer.getString();
            String method = buffer.getString();

            log.info("Authenticating user '{}' with method '{}'", username, method);
            Object identity = null;
            NamedFactory<UserAuth> factory = NamedFactory.Utils.get(userAuthFactories, method);
            if (factory != null) {
                UserAuth auth = factory.create();
                try {
                    identity = auth.auth(this, username, buffer);
                    if (identity == null) {
                        // authentication is still ongoing
                        log.info("Authentication not finished");
                        return;
                    } else {
                        log.info("Authentication succeeded");
                    }
                } catch (Exception e) {
                    // Continue
                    log.info("Authentication failed: {}", e.getMessage());
                }
            } else {
                log.info("Unsupported authentication method '{}'", method);
            }
            if (identity != null) {
                buffer = createBuffer(SshConstants.Message.SSH_MSG_USERAUTH_SUCCESS);
                writePacket(buffer);
                state = State.Running;
                authed = true;
                this.username = username;
                unscheduleAuthTimer();
            } else {
                buffer = createBuffer(SshConstants.Message.SSH_MSG_USERAUTH_FAILURE);
                NamedFactory.Utils.remove(userAuthFactories, "none"); // 'none' MUST NOT be listed
                buffer.putString(NamedFactory.Utils.getNames(userAuthFactories));
                buffer.putByte((byte) 0);
                writePacket(buffer);
            }
        }
    }

    public KeyPair getHostKey() {
        return factoryManager.getKeyPairProvider().loadKey(negociated[SshConstants.PROPOSAL_SERVER_HOST_KEY_ALGS]);
    }

    private void channelOpen(Buffer buffer) throws Exception {
        String type = buffer.getString();
        int id = buffer.getInt();
        int rwsize = buffer.getInt();
        int rmpsize = buffer.getInt();

        log.info("Received SSH_MSG_CHANNEL_OPEN {}", type);

        ServerChannel channel = null;
        for (NamedFactory<ServerChannel> factory : getServerFactoryManager().getChannelFactories()) {
            if (factory.getName().equals(type)) {
                channel = factory.create();
                break;
            }
        }
        if (channel == null) {
            buffer = createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_OPEN_FAILURE);
            buffer.putInt(id);
            buffer.putInt(SshConstants.SSH_OPEN_UNKNOWN_CHANNEL_TYPE);
            buffer.putString("Unsupported channel type: " + type);
            buffer.putString("");
            writePacket(buffer);
            return;
        }

        int channelId;
        synchronized (channels) {
            channelId = ++nextChannelId;
        }
        channels.put(channelId, channel);
        channel.init(this, channelId, id, rwsize, rmpsize);
        buffer = createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
        buffer.putInt(id);
        buffer.putInt(channelId);
        buffer.putInt(channel.getLocalWindow().getSize());
        buffer.putInt(channel.getLocalWindow().getPacketSize());
        writePacket(buffer);
    }

    private void globalRequest(Buffer buffer) throws Exception {
        String req = buffer.getString();
        log.info("Received SSH_MSG_GLOBAL_REQUEST {}" ,req);
        log.error("Unknown global request: {}", req);
        buffer = createBuffer(SshConstants.Message.SSH_MSG_REQUEST_FAILURE);
        writePacket(buffer);
    }


}
