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
package org.apache.sshd.server.channel;

import java.io.IOException;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetSocketAddress;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.service.IoConnector;
import org.apache.mina.core.service.IoHandler;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.nio.NioSocketConnector;
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
import org.apache.sshd.server.ForwardingFilter;
import org.apache.sshd.server.session.ServerSession;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelDirectTcpip extends AbstractServerChannel {

    public static class Factory implements NamedFactory<Channel> {

        public String getName() {
            return "direct-tcpip";
        }

        public Channel create() {
            return new ChannelDirectTcpip();
        }
    }

    private IoConnector connector;
    private IoSession ioSession;
    private OutputStream out;

    public ChannelDirectTcpip() {
    }

    protected OpenFuture doInit(Buffer buffer) {
        final OpenFuture f = new DefaultOpenFuture(this);

        String hostToConnect = buffer.getString();
        int portToConnect = buffer.getInt();
        String originatorIpAddress = buffer.getString();
        int originatorPort = buffer.getInt();
        log.info("Receiving request for direct tcpip: hostToConnect={}, portToConnect={}, originatorIpAddress={}, originatorPort={}",
                new Object[] { hostToConnect, portToConnect, originatorIpAddress, originatorPort });

        InetSocketAddress address;
        try {
            address = new InetSocketAddress(hostToConnect, portToConnect);
        } catch (RuntimeException e) {
            address = null;
        }

        final ServerSession serverSession = (ServerSession)getSession();
        final ForwardingFilter filter = serverSession.getServerFactoryManager().getForwardingFilter();
        if (address == null || filter == null || !filter.canConnect(address, serverSession)) {
            super.close(true);
            f.setException(new OpenChannelException(SshConstants.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, "connect denied"));
            return f;
        }

        connector = new NioSocketConnector();
        out = new ChannelOutputStream(this, remoteWindow, log, SshConstants.Message.SSH_MSG_CHANNEL_DATA);
        IoHandler handler = new IoHandlerAdapter() {
            @Override
            public void messageReceived(IoSession session, Object message) throws Exception {
                IoBuffer ioBuffer = (IoBuffer) message;
                int r = ioBuffer.remaining();
                byte[] b = new byte[r];
                ioBuffer.get(b, 0, r);
                out.write(b, 0, r);
                out.flush();
            }

            @Override
            public void sessionClosed(IoSession session) throws Exception {
                if (!closing) {
                    sendEof();
                }
            }
        };
        connector.setHandler(handler);
        ConnectFuture future = connector.connect(address);
        future.addListener(new IoFutureListener<ConnectFuture>() {
            public void operationComplete(ConnectFuture future) {
                if (future.isConnected()) {
                    ioSession = future.getSession();
                    f.setOpened();
                } else if (future.getException() != null) {
                    closeImmediately0();
                    if (future.getException() instanceof ConnectException) {
                        f.setException(new OpenChannelException(
                            SshConstants.SSH_OPEN_CONNECT_FAILED,
                            future.getException().getMessage(),
                            future.getException()));
                    } else {
                        f.setException(future.getException());
                    }
                }
            }
        });
        return f;
    }

    private void closeImmediately0() {
        // We need to close the channel immediately to remove it from the
        // server session's channel table and *not* send a packet to the
        // client.  A notification was already sent by our caller, or will
        // be sent after we return.
        //
        super.close(true);

        // We also need to dispose of the connector, but unfortunately we
        // are being invoked by the connector thread or the connector's
        // own processor thread.  Disposing of the connector within either
        // causes deadlock.  Instead create a new thread to dispose of the
        // connector in the background.
        //
        new Thread("ChannelDirectTcpip-ConnectorCleanup") {
            @Override
            public void run() {
                connector.dispose();
            }
        }.start();
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
        close(false);
    }

    protected void doWriteData(byte[] data, int off, int len) throws IOException {
        IoBuffer buf = IoBuffer.allocate(len);
        buf.put(data, off, len);
        buf.flip();
        ioSession.write(buf);
    }

    protected void doWriteExtendedData(byte[] data, int off, int len) throws IOException {
        throw new UnsupportedOperationException("DirectTcpip channel does not support extended data");
    }

    public void handleRequest(Buffer buffer) throws IOException {
        log.info("Received SSH_MSG_CHANNEL_REQUEST on channel {}", id);
        String type = buffer.getString();
        log.info("Received channel request: {}", type);
        buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_FAILURE, 0);
        buffer.putInt(recipient);
        session.writePacket(buffer);
    }
}
