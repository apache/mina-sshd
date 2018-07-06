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
package org.apache.sshd.common.forward;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

import org.apache.sshd.client.channel.AbstractClientChannel;
import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class TcpipClientChannel extends AbstractClientChannel implements ForwardingTunnelEndpointsProvider {
    /**
     * Type of channel being created. The type's {@link #getName()}
     * method returns the SSH request type
     */
    public enum Type implements NamedResource {
        Direct("direct-tcpip"),
        Forwarded("forwarded-tcpip");

        public static final Set<Type> VALUES =
                Collections.unmodifiableSet(EnumSet.allOf(Type.class));

        private final String channelType;

        Type(String channelType) {
            this.channelType = channelType;
        }

        @Override
        public String getName() {
            return channelType;
        }
    }

    private final Type typeEnum;
    private final IoSession serverSession;
    private final SshdSocketAddress remote;
    private SshdSocketAddress tunnelEntrance;
    private SshdSocketAddress tunnelExit;

    public TcpipClientChannel(Type type, IoSession serverSession, SshdSocketAddress remote) {
        super(Objects.requireNonNull(type, "No type specified").getName());
        this.typeEnum = type;
        this.serverSession = Objects.requireNonNull(serverSession, "No server session provided");
        this.remote = remote;
    }

    public OpenFuture getOpenFuture() {
        return openFuture;
    }

    public Type getTcpipChannelType() {
        return typeEnum;
    }

    @Override
    public synchronized OpenFuture open() throws IOException {
        InetSocketAddress src;
        InetSocketAddress dst;
        Type openType = getTcpipChannelType();
        switch (openType) {
            case Direct: {
                src = (InetSocketAddress) serverSession.getRemoteAddress();
                dst = this.remote.toInetSocketAddress();
                InetSocketAddress loc = (InetSocketAddress) serverSession.getLocalAddress();
                tunnelEntrance = new SshdSocketAddress(loc.getHostString(), loc.getPort());
                tunnelExit = new SshdSocketAddress(dst.getHostString(), dst.getPort());
                break;
            }
            case Forwarded:
                src = (InetSocketAddress) serverSession.getRemoteAddress();
                dst = (InetSocketAddress) serverSession.getLocalAddress();
                tunnelEntrance = new SshdSocketAddress(src.getHostString(), src.getPort());
                tunnelExit = new SshdSocketAddress(dst.getHostString(), dst.getPort());
                break;
            default:
                throw new SshException("Unknown client channel type: " + openType);
        }

        if (closeFuture.isClosed()) {
            throw new SshException("Session has been closed");
        }

        openFuture = new DefaultOpenFuture(src, lock);
        if (log.isDebugEnabled()) {
            log.debug("open({}) send SSH_MSG_CHANNEL_OPEN", this);
        }

        Session session = getSession();
        InetAddress srcAddress = src.getAddress();
        String srcHost = srcAddress.getHostAddress();
        InetAddress dstAddress = dst.getAddress();
        String dstHost = dstAddress.getHostAddress();
        Window wLocal = getLocalWindow();
        String type = getChannelType();
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_OPEN,
            type.length() + srcHost.length() + dstHost.length() + Long.SIZE);
        buffer.putString(type);
        buffer.putInt(getId());
        buffer.putInt(wLocal.getSize());
        buffer.putInt(wLocal.getPacketSize());
        buffer.putString(dstHost);
        buffer.putInt(dst.getPort());
        buffer.putString(srcHost);
        buffer.putInt(src.getPort());
        writePacket(buffer);
        return openFuture;
    }

    @Override
    protected synchronized void doOpen() throws IOException {
        if (streaming == Streaming.Async) {
            throw new IllegalArgumentException("Asynchronous streaming isn't supported yet on this channel");
        }
        out = new ChannelOutputStream(this, getRemoteWindow(), log, SshConstants.SSH_MSG_CHANNEL_DATA, true);
        invertedIn = out;
    }

    @Override
    protected Closeable getInnerCloseable() {
        return builder().sequential(serverSession, super.getInnerCloseable()).build();
    }

    @Override
    protected synchronized void doWriteData(byte[] data, int off, long len) throws IOException {
        ValidateUtils.checkTrue(len <= Integer.MAX_VALUE, "Data length exceeds int boundaries: %d", len);
        // Make sure we copy the data as the incoming buffer may be reused
        Buffer buf = ByteArrayBuffer.getCompactClone(data, off, (int) len);
        Window wLocal = getLocalWindow();
        wLocal.consumeAndCheck(len);
        serverSession.writePacket(buf);
    }

    @Override
    protected void doWriteExtendedData(byte[] data, int off, long len) throws IOException {
        throw new UnsupportedOperationException(getChannelType() + "Tcpip channel does not support extended data");
    }

    @Override
    public SshdSocketAddress getTunnelEntrance() {
        return tunnelEntrance;
    }

    @Override
    public SshdSocketAddress getTunnelExit() {
        return tunnelExit;
    }
}
