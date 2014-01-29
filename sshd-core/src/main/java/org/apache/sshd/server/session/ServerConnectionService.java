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

import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Channel;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Service;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.SshdSocketAddress;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.session.AbstractConnectionService;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.channel.OpenChannelException;

/**
 * Server side <code>ssh-connection</code> service.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ServerConnectionService extends AbstractConnectionService {

    public static class Factory implements ServiceFactory {

        public String getName() {
            return "ssh-connection";
        }

        public Service create(Session session) throws IOException {
            return new ServerConnectionService(session);
        }
    }


    private boolean allowMoreSessions = true;

    protected ServerConnectionService(Session s) throws SshException {
        super(s);
        if (!(s instanceof ServerSession)) {
            throw new IllegalStateException("Server side service used on client side");
        }
        ServerSession session = (ServerSession) s;
        if (!session.isAuthenticated()) {
            throw new SshException("Session is not authenticated");
        }
    }

    public void process(SshConstants.Message cmd, Buffer buffer) throws Exception {
        switch (cmd) {
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
            case SSH_MSG_GLOBAL_REQUEST:
                globalRequest(buffer);
                break;
            default:
                throw new IllegalStateException("Unsupported command: " + cmd);
        }
    }

    private void channelOpen(Buffer buffer) throws Exception {
        String type = buffer.getString();
        final int id = buffer.getInt();
        final int rwsize = buffer.getInt();
        final int rmpsize = buffer.getInt();

        log.debug("Received SSH_MSG_CHANNEL_OPEN {}", type);

        if (closing) {
            Buffer buf = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_OPEN_FAILURE, 0);
            buf.putInt(id);
            buf.putInt(SshConstants.SSH_OPEN_CONNECT_FAILED);
            buf.putString("SSH server is shutting down: " + type);
            buf.putString("");
            session.writePacket(buf);
            return;
        }
        if (!allowMoreSessions) {
            Buffer buf = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_OPEN_FAILURE, 0);
            buf.putInt(id);
            buf.putInt(SshConstants.SSH_OPEN_CONNECT_FAILED);
            buf.putString("additional sessions disabled");
            buf.putString("");
            session.writePacket(buf);
            return;
        }

        final Channel channel = NamedFactory.Utils.create(session.getFactoryManager().getChannelFactories(), type);
        if (channel == null) {
            Buffer buf = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_OPEN_FAILURE, 0);
            buf.putInt(id);
            buf.putInt(SshConstants.SSH_OPEN_UNKNOWN_CHANNEL_TYPE);
            buf.putString("Unsupported channel type: " + type);
            buf.putString("");
            session.writePacket(buf);
            return;
        }

        final int channelId = registerChannel(channel);
        channel.open(id, rwsize, rmpsize, buffer).addListener(new SshFutureListener<OpenFuture>() {
            public void operationComplete(OpenFuture future) {
                try {
                    if (future.isOpened()) {
                        Buffer buf = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_OPEN_CONFIRMATION, 0);
                        buf.putInt(id);
                        buf.putInt(channelId);
                        buf.putInt(channel.getLocalWindow().getSize());
                        buf.putInt(channel.getLocalWindow().getPacketSize());
                        session.writePacket(buf);
                    } else if (future.getException() != null) {
                        Buffer buf = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_OPEN_FAILURE, 0);
                        buf.putInt(id);
                        if (future.getException() instanceof OpenChannelException) {
                            buf.putInt(((OpenChannelException) future.getException()).getReasonCode());
                            buf.putString(future.getException().getMessage());
                        } else {
                            buf.putInt(0);
                            buf.putString("Error opening channel: " + future.getException().getMessage());
                        }
                        buf.putString("");
                        session.writePacket(buf);
                    }
                } catch (IOException e) {
                    session.exceptionCaught(e);
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
                SshdSocketAddress bound = tcpipForwarder.localPortForwardingRequested(new SshdSocketAddress(address, port));
                port = bound.getPort();
                if (wantReply){
                    buffer = session.createBuffer(SshConstants.Message.SSH_MSG_REQUEST_SUCCESS, 0);
                    buffer.putInt(port);
                    session.writePacket(buffer);
                }
            } catch (Exception e) {
                log.debug("Error starting tcpip forward", e);
                if (wantReply) {
                    buffer = session.createBuffer(SshConstants.Message.SSH_MSG_REQUEST_FAILURE, 0);
                    session.writePacket(buffer);
                }
            }
            return;
        } else if (req.equals("cancel-tcpip-forward")) {
            String address = buffer.getString();
            int port = buffer.getInt();
            tcpipForwarder.localPortForwardingCancelled(new SshdSocketAddress(address, port));
            if (wantReply){
                buffer = session.createBuffer(SshConstants.Message.SSH_MSG_REQUEST_SUCCESS, 0);
                session.writePacket(buffer);
            }
            return;
        } else {
            log.debug("Received SSH_MSG_GLOBAL_REQUEST {}", req);
            log.warn("Unknown global request: {}", req);
        }
        if (wantReply) {
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_REQUEST_FAILURE, 0);
            session.writePacket(buffer);
        }
    }

    public String initAgentForward() throws IOException {
        return agentForward.initialize();
    }

    public String createX11Display(boolean singleConnection, String authenticationProtocol, String authenticationCookie, int screen) throws IOException {
        return x11Forward.createDisplay(singleConnection, authenticationProtocol, authenticationCookie, screen);
    }

}
