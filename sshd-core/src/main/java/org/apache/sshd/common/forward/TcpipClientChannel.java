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
import org.apache.sshd.common.channel.ChannelAsyncInputStream;
import org.apache.sshd.common.channel.ChannelAsyncOutputStream;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.channel.LocalWindow;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class TcpipClientChannel extends AbstractClientChannel implements ForwardingTunnelEndpointsProvider {
    /**
     * Type of channel being created. The type's {@link #getName()} method returns the SSH request type
     */
    public enum Type implements NamedResource {
        Direct("direct-tcpip"),
        Forwarded("forwarded-tcpip");

        public static final Set<Type> VALUES = Collections.unmodifiableSet(EnumSet.allOf(Type.class));

        private final String channelType;

        Type(String channelType) {
            this.channelType = channelType;
        }

        @Override
        public String getName() {
            return channelType;
        }
    }

    protected final SshdSocketAddress remote;
    protected final ChannelToPortHandler port;
    protected SshdSocketAddress localEntry;

    private final Type typeEnum;
    private SshdSocketAddress tunnelEntrance;
    private SshdSocketAddress tunnelExit;

    public TcpipClientChannel(Type type, IoSession serverSession, SshdSocketAddress remote) {
        super(Objects.requireNonNull(type, "No type specified").getName());
        this.typeEnum = type;
        this.port = createChannelToPortHandler(Objects.requireNonNull(serverSession, "No server session provided"));
        this.localEntry = new SshdSocketAddress((InetSocketAddress) serverSession.getLocalAddress());
        this.remote = remote;
    }

    protected ChannelToPortHandler createChannelToPortHandler(IoSession session) {
        return new ChannelToPortHandler(session, this);
    }

    public Type getTcpipChannelType() {
        return typeEnum;
    }

    public void updateLocalForwardingEntry(LocalForwardingEntry entry) {
        Objects.requireNonNull(entry, "No local forwarding entry provided");
        // OpenSSH requires the host string it passed in the tcpip-forward global request: it compares both host and
        // port and refuses the forwarding request when it doesn't match in the forwarded-tcpip request.
        //
        // Note: Apache MINA sshd is currently more lenient in that respect and compares only the port. RFC 4254
        // states that "Implementations MUST reject these messages unless they have previously requested a remote TCP/IP
        // port forwarding with the given port number"; it does not require the host name to be checked.
        localEntry = new SshdSocketAddress(entry.getLocalAddress().getHostName(), entry.getBoundAddress().getPort());
    }

    @Override
    public synchronized OpenFuture open() throws IOException {
        InetSocketAddress src;
        SshdSocketAddress dst;
        IoSession portSession = port.getPortSession();
        InetSocketAddress loc = (InetSocketAddress) portSession.getLocalAddress();
        Type openType = getTcpipChannelType();
        switch (openType) {
            case Direct:
                src = (InetSocketAddress) portSession.getRemoteAddress();
                dst = this.remote;
                tunnelEntrance = new SshdSocketAddress(loc.getHostString(), loc.getPort());
                tunnelExit = new SshdSocketAddress(dst.getHostName(), dst.getPort());
                break;
            case Forwarded:
                src = (InetSocketAddress) portSession.getRemoteAddress();
                dst = localEntry;
                tunnelEntrance = new SshdSocketAddress(src.getHostString(), src.getPort());
                tunnelExit = new SshdSocketAddress(loc.getHostString(), loc.getPort());
                break;
            default:
                throw new SshException("Unknown client channel type: " + openType);
        }

        if (closeFuture.isClosed()) {
            throw new SshException("Session has been closed");
        }

        openFuture = new DefaultOpenFuture(src, futureLock);
        if (log.isDebugEnabled()) {
            log.debug("open({}) send SSH_MSG_CHANNEL_OPEN", this);
        }

        Session session = getSession();
        String srcHost = src.getHostString();
        String dstHost = dst.getHostName();
        LocalWindow wLocal = getLocalWindow();
        String type = getChannelType();
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_OPEN,
                type.length() + srcHost.length() + dstHost.length() + Long.SIZE);
        buffer.putString(type);
        buffer.putUInt(getChannelId());
        buffer.putUInt(wLocal.getSize());
        buffer.putUInt(wLocal.getPacketSize());
        buffer.putString(dstHost);
        buffer.putUInt(dst.getPort());
        buffer.putString(srcHost);
        buffer.putUInt(src.getPort());
        writePacket(buffer);
        return openFuture;
    }

    @Override
    protected synchronized void doOpen() throws IOException {
        if (streaming == Streaming.Async) {
            asyncIn = new ChannelAsyncOutputStream(this, SshConstants.SSH_MSG_CHANNEL_DATA) {
                @SuppressWarnings("synthetic-access")
                @Override
                protected CloseFuture doCloseGracefully() {
                    // First get the last packets out
                    CloseFuture result = super.doCloseGracefully();
                    result.addListener(f -> {
                        try {
                            // The channel writes EOF directly through the SSH session
                            sendEof();
                        } catch (IOException e) {
                            getSession().exceptionCaught(e);
                        }
                    });
                    return result;
                }
            };
            asyncOut = new ChannelAsyncInputStream(this);
        } else {
            out = new ChannelOutputStream(
                    this, getRemoteWindow(), log, SshConstants.SSH_MSG_CHANNEL_DATA, true);
            invertedIn = out;
        }
    }

    @Override
    protected Closeable getInnerCloseable() {
        return builder()
                .sequential(port.getPortSession(), super.getInnerCloseable())
                .build();
    }

    @Override
    protected void doWriteData(byte[] data, int off, long len) throws IOException {
        port.sendToPort(SshConstants.SSH_MSG_CHANNEL_DATA, data, off, len);
    }

    @Override
    protected void doWriteExtendedData(byte[] data, int off, long len) throws IOException {
        throw new UnsupportedOperationException(getChannelType() + " Tcpip channel does not support extended data");
    }

    @Override
    public void handleEof() throws IOException {
        super.handleEof();
        port.handleEof();
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
