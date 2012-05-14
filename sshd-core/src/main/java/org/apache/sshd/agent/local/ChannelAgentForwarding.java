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
package org.apache.sshd.agent.local;

import java.io.IOException;
import java.io.OutputStream;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.common.AbstractAgentClient;
import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Channel;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.channel.AbstractServerChannel;

/**
 * The client side channel that will receive requests forwards by the SSH server.
 */
public class ChannelAgentForwarding extends AbstractServerChannel {

    public static class Factory implements NamedFactory<Channel> {

        public String getName() {
            return "auth-agent@openssh.com";
        }

        public Channel create() {
            return new ChannelAgentForwarding();
        }
    }

    private String authSocket;
    private long pool;
    private long handle;
    private Thread thread;
    private OutputStream out;
    private SshAgent agent;
    private AgentClient client;

    public ChannelAgentForwarding() {
    }

    protected OpenFuture doInit(Buffer buffer) {
        final OpenFuture f = new DefaultOpenFuture(this);
        try {
            out = new ChannelOutputStream(this, remoteWindow, log, SshConstants.Message.SSH_MSG_CHANNEL_DATA);
            agent = session.getFactoryManager().getAgentFactory().createClient(session);
            client = new AgentClient();
            f.setOpened();

        } catch (Exception e) {
            f.setException(e);
        }
        return f;
    }

    private void closeImmediately0() {
        // We need to close the channel immediately to remove it from the
        // server session's channel table and *not* send a packet to the
        // client.  A notification was already sent by our caller, or will
        // be sent after we return.
        //
        super.close(true);

        // We also need to close the socket.
        //
//        Socket.close(handle);
    }

    public CloseFuture close(boolean immediately) {
        return super.close(immediately).addListener(new SshFutureListener() {
            public void operationComplete(SshFuture sshFuture) {
                closeImmediately0();
            }
        });
    }

    @Override
    public void handleEof() throws IOException {
        super.handleEof();
//        close(true);
    }

    protected void doWriteData(byte[] data, int off, int len) throws IOException {
        client.messageReceived(new Buffer(data, off, len));
    }

    protected void doWriteExtendedData(byte[] data, int off, int len) throws IOException {
        throw new UnsupportedOperationException("AgentForward channel does not support extended data");
    }

    public void handleRequest(Buffer buffer) throws IOException {
        log.info("Received SSH_MSG_CHANNEL_REQUEST on channel {}", id);
        String type = buffer.getString();
        log.info("Received channel request: {}", type);
        buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_FAILURE, 0);
        buffer.putInt(recipient);
        session.writePacket(buffer);
    }

    protected class AgentClient extends AbstractAgentClient {

        public AgentClient() {
            super(agent);
        }

        @Override
        protected void reply(Buffer buf) throws IOException {
            out.write(buf.array(), buf.rpos(), buf.available());
            out.flush();
        }
    }

}
