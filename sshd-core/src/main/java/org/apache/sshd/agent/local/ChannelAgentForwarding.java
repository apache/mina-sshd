/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.agent.local;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;
import java.util.Objects;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.agent.common.AbstractAgentClient;
import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.server.channel.AbstractServerChannel;

/**
 * The client side channel that will receive requests forwards by the SSH server.
 */
public class ChannelAgentForwarding extends AbstractServerChannel {
    private OutputStream out;
    private SshAgent agent;
    private AgentClient client;

    public ChannelAgentForwarding(CloseableExecutorService executor) {
        super("", Collections.emptyList(), executor);
    }

    @Override
    protected OpenFuture doInit(Buffer buffer) {
        OpenFuture f = new DefaultOpenFuture(this, this);
        String changeEvent = "auth-agent";
        try {
            out = new ChannelOutputStream(
                    this, getRemoteWindow(), log, SshConstants.SSH_MSG_CHANNEL_DATA, true);

            Session session = getSession();
            FactoryManager manager = Objects.requireNonNull(session.getFactoryManager(), "No factory manager");
            SshAgentFactory factory = Objects.requireNonNull(manager.getAgentFactory(), "No agent factory");
            agent = factory.createClient(manager);
            client = new AgentClient();

            signalChannelOpenSuccess();
            f.setOpened();
        } catch (Throwable t) {
            Throwable e = GenericUtils.peelException(t);
            changeEvent = e.getClass().getSimpleName();
            signalChannelOpenFailure(e);
            f.setException(e);
        } finally {
            notifyStateChanged(changeEvent);
        }
        return f;
    }

    @Override
    public void handleEof() throws IOException {
        // Close agent forwarding channel
        try {
            if ((agent != null) && agent.isOpen()) {
                agent.close();
            }
        } finally {
            super.handleEof();
        }
    }

    private void closeImmediately0() {
        // We need to close the channel immediately to remove it from the
        // server session's channel table and *not* send a packet to the
        // client. A notification was already sent by our caller, or will
        // be sent after we return.
        try {
            if ((agent != null) && agent.isOpen()) {
                try {
                    agent.close();
                } catch (IOException e) {
                    log.error("closeImmediately0({}) Failed ({}) to close open local agent: {}",
                            this, e.getClass().getSimpleName(), e.getMessage());
                }
            }
        } finally {
            super.close(true);
        }
    }

    @Override
    protected Closeable getInnerCloseable() {
        return builder()
                .close(super.getInnerCloseable())
                .run(toString(), this::closeImmediately0)
                .build();
    }

    @Override
    protected void doWriteData(byte[] data, int off, long len) throws IOException {
        ValidateUtils.checkTrue(len <= Integer.MAX_VALUE,
                "Data length exceeds int boundaries: %d", len);
        client.messageReceived(new ByteArrayBuffer(data, off, (int) len));
    }

    @Override
    protected void doWriteExtendedData(byte[] data, int off, long len) throws IOException {
        throw new UnsupportedOperationException(
                "AgentForward channel does not support extended data");
    }

    @SuppressWarnings("synthetic-access")
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
