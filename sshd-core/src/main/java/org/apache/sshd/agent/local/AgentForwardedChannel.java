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
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.util.Queue;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.common.AbstractAgentProxy;
import org.apache.sshd.client.channel.AbstractClientChannel;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.core.CoreModuleProperties;

public class AgentForwardedChannel extends AbstractClientChannel {
    /**
     * Time to wait for new incoming messages before checking if the channel is still active
     */
    public static final String MESSAGE_POLL_FREQUENCY = "agent-fwd-channel-message-poll-time";

    /**
     * Default value for {@value #MESSAGE_POLL_FREQUENCY}
     */
    public static final long DEFAULT_MESSAGE_POLL_FREQUENCY = TimeUnit.MINUTES.toMillis(2L);

    private final Queue<Buffer> messages = new ArrayBlockingQueue<>(10);
    private final Buffer receiveBuffer = new ByteArrayBuffer();

    public AgentForwardedChannel(String channelType) {
        super(channelType);
        // Wake up waitForMessageBuffer to sense the closure
        addCloseFutureListener(f -> {
            synchronized (messages) {
                messages.notifyAll();
            }
        });
    }

    public SshAgent getAgent() {
        AbstractAgentProxy rtn = new AbstractAgentProxy(null) {
            private final AtomicBoolean open = new AtomicBoolean(true);

            @Override
            public boolean isOpen() {
                return open.get();
            }

            @Override
            protected Buffer request(Buffer buffer) throws IOException {
                return AgentForwardedChannel.this.request(buffer);
            }

            @Override
            public void close() throws IOException {
                if (open.getAndSet(false)) {
                    AgentForwardedChannel.this.close(false);
                    super.close();
                }
            }
        };

        String chType = PropertyResolverUtils.getString(
                getSession(), CoreModuleProperties.AGENT_FORWARDING_TYPE);
        rtn.setChannelType(chType);
        return rtn;
    }

    protected Buffer request(Buffer buffer) throws IOException {
        int reqLen = buffer.available();
        synchronized (messages) {
            OutputStream outputStream = getInvertedIn();
            outputStream.write(buffer.array(), buffer.rpos(), reqLen);
            outputStream.flush();

            Window wLocal = getLocalWindow();
            wLocal.consumeAndCheck(reqLen);
            return waitForMessageBuffer();
        }
    }

    // NOTE: assumes messages lock is obtained prior to calling this method
    protected Buffer waitForMessageBuffer() throws IOException {
        Session session = getSession();
        long idleTimeout = PropertyResolverUtils.getLongProperty(
                session, MESSAGE_POLL_FREQUENCY, DEFAULT_MESSAGE_POLL_FREQUENCY);
        if (idleTimeout <= 0L) {
            idleTimeout = DEFAULT_MESSAGE_POLL_FREQUENCY;
        }

        boolean traceEnabled = log.isTraceEnabled();
        for (int count = 1;; count++) {
            if (isClosing() || (!isOpen())) {
                throw new SshException("Channel is being closed");
            }

            if (!messages.isEmpty()) {
                return messages.poll();
            }

            if (traceEnabled) {
                log.trace("waitForMessageBuffer({}) wait iteration #{}", this, count);
            }

            try {
                messages.wait(idleTimeout);
            } catch (InterruptedException e) {
                throw (IOException) new InterruptedIOException(
                        "Interrupted while waiting for messages at iteration #" + count)
                                .initCause(e);
            }
        }
    }

    @Override
    protected void doOpen() throws IOException {
        ValidateUtils.checkTrue(
                !Streaming.Async.equals(streaming), "Asynchronous streaming isn't supported yet on this channel");
        invertedIn = new ChannelOutputStream(
                this, getRemoteWindow(), log, SshConstants.SSH_MSG_CHANNEL_DATA, true);
    }

    @Override
    protected void doWriteData(byte[] data, int off, long len) throws IOException {
        ValidateUtils.checkTrue(len <= Integer.MAX_VALUE,
                "Data length exceeds int boundaries: %d", len);

        Buffer message = null;
        synchronized (receiveBuffer) {
            receiveBuffer.putBuffer(new ByteArrayBuffer(data, off, (int) len));
            if (receiveBuffer.available() >= Integer.BYTES) {
                off = receiveBuffer.rpos();
                len = receiveBuffer.getInt();
                receiveBuffer.rpos(off);
                if (receiveBuffer.available() >= (Integer.BYTES + len)) {
                    message = new ByteArrayBuffer(receiveBuffer.getBytes());
                    receiveBuffer.compact();
                }
            }
        }
        if (message != null) {
            synchronized (messages) {
                messages.offer(message);
                messages.notifyAll();
            }
        }
    }
}
