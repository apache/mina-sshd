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
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.common.AbstractAgentProxy;
import org.apache.sshd.client.channel.AbstractClientChannel;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

public class AgentForwardedChannel extends AbstractClientChannel {

    private final Queue<Buffer> messages = new ArrayBlockingQueue<>(10);
    private final Buffer receiveBuffer = new ByteArrayBuffer();

    public AgentForwardedChannel() {
        super("auth-agent@openssh.com");
    }

    public SshAgent getAgent() {
        return new AbstractAgentProxy() {
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
    }

    protected Buffer request(Buffer buffer) throws IOException {
        synchronized (messages) {
            try {
                OutputStream outputStream = getInvertedIn();
                outputStream.write(buffer.array(), buffer.rpos(), buffer.available());
                outputStream.flush();

                Window wLocal = getLocalWindow();
                wLocal.consumeAndCheck(buffer.available());
                if (messages.isEmpty()) {
                    messages.wait();
                }
                return messages.poll();
            } catch (InterruptedException e) {
                throw (IOException) new InterruptedIOException("Interrupted while polling for messages").initCause(e);
            }
        }
    }

    @Override
    protected void doOpen() throws IOException {
        ValidateUtils.checkTrue(!Streaming.Async.equals(streaming), "Asynchronous streaming isn't supported yet on this channel");
        invertedIn = new ChannelOutputStream(this, getRemoteWindow(), log, SshConstants.SSH_MSG_CHANNEL_DATA, true);
    }

    @Override
    protected void doWriteData(byte[] data, int off, int len) throws IOException {
        Buffer message = null;
        synchronized (receiveBuffer) {
            receiveBuffer.putBuffer(new ByteArrayBuffer(data, off, len));
            if (receiveBuffer.available() >= 4) {
                off = receiveBuffer.rpos();
                len = receiveBuffer.getInt();
                receiveBuffer.rpos(off);
                if (receiveBuffer.available() >= 4 + len) {
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
