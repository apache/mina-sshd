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
package org.apache.sshd.client.channel;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.sshd.client.SshdSocketAddress;
import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.util.Buffer;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelDirectTcpip extends AbstractClientChannel {

    private final SshdSocketAddress local;
    private final SshdSocketAddress remote;
    private final PipedOutputStream pipe = new PipedOutputStream();

    public ChannelDirectTcpip(SshdSocketAddress local, SshdSocketAddress remote) {
        super("direct-tcpip");
        if (local == null) {
            try {
                local = new SshdSocketAddress(InetAddress.getLocalHost().getHostName(), 0);
            } catch (UnknownHostException e) {
                throw new IllegalStateException("Unable to retrieve local host name");
            }
        }
        if (remote == null) {
            throw new IllegalArgumentException("Remote address must not be null");
        }
        this.local = local;
        this.remote = remote;
    }

    @Override
    protected OpenFuture internalOpen() throws Exception {
        if (closeFuture.isClosed()) {
            throw new SshException("Session has been closed");
        }
        openFuture = new DefaultOpenFuture(lock);
        log.info("Send SSH_MSG_CHANNEL_OPEN on channel {}", id);
        Buffer buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_OPEN, 0);
        buffer.putString(type);
        buffer.putInt(id);
        buffer.putInt(localWindow.getSize());
        buffer.putInt(localWindow.getPacketSize());
        buffer.putString(remote.getHostName());
        buffer.putInt(remote.getPort());
        buffer.putString(local.getHostName());
        buffer.putInt(local.getPort());
        session.writePacket(buffer);
        return openFuture;
    }

    @Override
    protected void doOpen() throws Exception {
        out = new ChannelOutputStream(this, remoteWindow, log, SshConstants.Message.SSH_MSG_CHANNEL_DATA);
        in = new PipedInputStream(pipe);
    }

    public OpenFuture open() throws Exception {
        return internalOpen();
    }

    @Override
    protected void doWriteData(byte[] data, int off, int len) throws IOException {
        pipe.write(data, off, len);
        pipe.flush();
        localWindow.consumeAndCheck(len);
    }

}
