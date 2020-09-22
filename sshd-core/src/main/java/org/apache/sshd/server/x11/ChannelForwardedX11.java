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
package org.apache.sshd.server.x11;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.apache.sshd.client.channel.AbstractClientChannel;
import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelForwardedX11 extends AbstractClientChannel {
    private final IoSession serverSession;

    public ChannelForwardedX11(IoSession serverSession) {
        super("x11");
        this.serverSession = serverSession;
    }

    @Override
    public synchronized OpenFuture open() throws IOException {
        InetSocketAddress remote = (InetSocketAddress) serverSession.getRemoteAddress();
        if (closeFuture.isClosed()) {
            throw new SshException("Session has been closed");
        }
        openFuture = new DefaultOpenFuture(remote, futureLock);

        Session session = getSession();
        if (log.isDebugEnabled()) {
            log.debug("open({}) SSH_MSG_CHANNEL_OPEN", this);
        }

        InetAddress remoteAddress = remote.getAddress();
        String remoteHost = remoteAddress.getHostAddress();
        Window wLocal = getLocalWindow();
        String type = getChannelType();
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_OPEN,
                remoteHost.length() + type.length() + Integer.SIZE);
        buffer.putString(type);
        buffer.putInt(getId());
        buffer.putInt(wLocal.getSize());
        buffer.putInt(wLocal.getPacketSize());
        buffer.putString(remoteHost);
        buffer.putInt(remote.getPort());
        writePacket(buffer);
        return openFuture;
    }

    @Override
    protected synchronized void doOpen() throws IOException {
        if (Streaming.Async.equals(streaming)) {
            throw new IllegalArgumentException(
                    "Asynchronous streaming isn't supported yet on this channel");
        }

        out = new ChannelOutputStream(
                this, getRemoteWindow(), log, SshConstants.SSH_MSG_CHANNEL_DATA, true);
        invertedIn = out;
    }

    @Override
    protected Closeable getInnerCloseable() {
        return builder().sequential(serverSession, super.getInnerCloseable()).build();
    }

    @Override
    protected synchronized void doWriteData(byte[] data, int off, long len) throws IOException {
        ValidateUtils.checkTrue(len <= Integer.MAX_VALUE,
                "Data length exceeds int boundaries: %d", len);
        Window wLocal = getLocalWindow();
        wLocal.consumeAndCheck(len);
        // use a clone in case data buffer is re-used
        Buffer packet = ByteArrayBuffer.getCompactClone(data, off, (int) len);
        serverSession.writeBuffer(packet);
    }

    @Override
    public void handleEof() throws IOException {
        super.handleEof();
        serverSession.close(false);
    }
}
