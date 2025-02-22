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
package org.apache.sshd.common.io;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tests for low-level connections.
 */
class IoConnectionTest extends BaseTestSupport {

    private static final Logger LOG = LoggerFactory.getLogger(IoConnectionTest.class);

    @Test
    void connectorRace() throws Exception {
        CountDownLatch connectionMade = new CountDownLatch(1);
        CountDownLatch connectorClosing = new CountDownLatch(1);
        CountDownLatch futureTriggered = new CountDownLatch(1);
        CountDownLatch ioSessionClosed = new CountDownLatch(1);
        AtomicReference<IoSession> session = new AtomicReference<>();
        AtomicBoolean connectorIsClosing = new AtomicBoolean();
        AtomicBoolean sessionWaited = new AtomicBoolean();

        SshClient client = setupTestClient();
        IoServiceFactory serviceFactory = DefaultIoServiceFactoryFactory.getDefaultIoServiceFactoryFactoryInstance()
                .create(client);
        IoConnector connector = serviceFactory.createConnector(new IoHandler() {

            @Override
            public void sessionCreated(org.apache.sshd.common.io.IoSession session) throws Exception {
                connectionMade.countDown();
                sessionWaited.set(connectorClosing.await(5, TimeUnit.SECONDS));
            }

            @Override
            public void sessionClosed(org.apache.sshd.common.io.IoSession session) throws Exception {
                ioSessionClosed.countDown();
            }

            @Override
            public void exceptionCaught(org.apache.sshd.common.io.IoSession session, Throwable cause) throws Exception {
                // Nothing
            }

            @Override
            public void messageReceived(org.apache.sshd.common.io.IoSession session, Readable message) throws Exception {
                // Nothing; we're not actually sending or receiving data.
            }
        });
        NioSocketAcceptor acceptor = startEchoServer();
        try {
            InetSocketAddress connectAddress = new InetSocketAddress(InetAddress.getByName(TEST_LOCALHOST),
                    acceptor.getLocalAddress().getPort());
            IoConnectFuture future = connector.connect(connectAddress, null, null);
            connectionMade.await(5, TimeUnit.SECONDS);
            connector.close();
            connectorClosing.countDown();
            future.addListener(new SshFutureListener<IoConnectFuture>() {

                @Override
                public void operationComplete(IoConnectFuture future) {
                    session.set(future.getSession());
                    connectorIsClosing.set(!connector.isOpen());
                    futureTriggered.countDown();
                }
            });
            assertTrue(futureTriggered.await(5, TimeUnit.SECONDS));
            Throwable error = future.getException();
            if (error != null) {
                LOG.info("{}: Connect future was terminated exceptionally: {} ", getCurrentTestName(), error);
                error.printStackTrace();
            } else if (future.isCanceled()) {
                LOG.info("{}: Connect future was canceled", getCurrentTestName());
            }
            assertEquals(0, connectionMade.getCount());
            assertTrue(sessionWaited.get());
            assertNull(session.get());
            assertTrue(connectorIsClosing.get());
            // Since sessionCreated() was called we also expect sessionClosed() to get called eventually.
            assertTrue(ioSessionClosed.await(5, TimeUnit.SECONDS));
        } finally {
            acceptor.dispose(false);
        }
    }

    private NioSocketAcceptor startEchoServer() throws IOException {
        NioSocketAcceptor acceptor = new NioSocketAcceptor();
        acceptor.setHandler(new IoHandlerAdapter() {

            @Override
            public void messageReceived(org.apache.mina.core.session.IoSession session, Object message) throws Exception {
                IoBuffer recv = (IoBuffer) message;
                IoBuffer sent = IoBuffer.allocate(recv.remaining());
                sent.put(recv);
                sent.flip();
                session.write(sent);
            }
        });
        acceptor.setReuseAddress(true);
        acceptor.bind(new InetSocketAddress(0));
        return acceptor;
    }
}
