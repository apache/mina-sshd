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
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousServerSocketChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Port forwarding tests
 */
public abstract class AbstractServerCloseTestSupport extends BaseTestSupport {
    private static final String PAYLOAD = String.join("", Collections.nCopies(200, "This is significantly longer Test Data."));

    protected int testServerPort;
    private final Logger log;
    private AsynchronousServerSocketChannel testServerSock;

    protected AbstractServerCloseTestSupport() {
        log = LoggerFactory.getLogger(getClass());
    }

    /*
     * Start a server to forward to.
     *
     * This server sends PAYLOAD and then closes.
     */
    @BeforeEach
    public void startTestServer() throws Exception {
        InetSocketAddress sockAddr = new InetSocketAddress(TEST_LOCALHOST, 0);
        testServerSock = AsynchronousServerSocketChannel.open().bind(sockAddr);
        InetSocketAddress boundAddress = (InetSocketAddress) testServerSock.getLocalAddress();
        testServerPort = boundAddress.getPort();
        log.info("Listening on port {}", testServerPort);
        // Accept a connection
        testServerSock.accept(testServerSock,
                new CompletionHandler<AsynchronousSocketChannel, AsynchronousServerSocketChannel>() {
                    @Override
                    @SuppressWarnings("synthetic-access")
                    public void completed(AsynchronousSocketChannel sockChannel, AsynchronousServerSocketChannel serverSock) {
                        // a connection is accepted, start to accept next connection
                        serverSock.accept(serverSock, this);
                        log.info("Accepted new incoming connection");

                        ByteBuffer buf = ByteBuffer.wrap(PAYLOAD.getBytes(StandardCharsets.UTF_8));
                        // start to write payload to client
                        sockChannel.write(buf, sockChannel,
                                new CompletionHandler<Integer, AsynchronousSocketChannel>() {
                                    @Override
                                    public void completed(Integer result, AsynchronousSocketChannel channel) {
                                        // Write has been completed, close the
                                        // connection to the client
                                        try {
                                            channel.close();
                                        } catch (IOException e) {
                                            log.warn("Failed ({}) to close channel after write complete: {}",
                                                    e.getClass().getSimpleName(), e.getMessage());
                                        }
                                    }

                                    @Override
                                    public void failed(Throwable exc, AsynchronousSocketChannel channel) {
                                        log.error("Failed ({}) to write message to client: {}", exc.getClass().getSimpleName(),
                                                exc.getMessage());
                                    }
                                });
                    }

                    @Override
                    @SuppressWarnings("synthetic-access")
                    public void failed(Throwable exc, AsynchronousServerSocketChannel serverSock) {
                        log.error("Failed ({}) to accept incoming connection: {}", exc.getClass().getSimpleName(),
                                exc.getMessage(), exc);
                    }
                });
    }

    @AfterEach
    public void stopTestServer() throws Exception {
        testServerSock.close();
    }

    private void readInLoop(int serverPort) throws Exception {
        outputDebugMessage("readInLoop(port=%d)", serverPort);
        outputDebugMessage("expecting %d bytes", PAYLOAD.length());

        StringBuilder sb = new StringBuilder(PAYLOAD.length());
        try (Socket s = new Socket(TEST_LOCALHOST, serverPort)) {
            s.setSoTimeout(2000); // 300ms is too low for MINA

            try (InputStream inputStream = s.getInputStream()) {
                byte b[] = new byte[PAYLOAD.length() / 10];
                while (true) {
                    int readLen = inputStream.read(b);
                    if (readLen == -1) {
                        break;
                    }
                    outputDebugMessage("readInLoop(port=%d) read %d bytes", serverPort, readLen);

                    String fragment = new String(b, 0, readLen, StandardCharsets.UTF_8);
                    sb.append(fragment);
                    Thread.sleep(25L);
                }
            }
        } catch (IOException e) {
            String readData = sb.toString();
            assertEquals(PAYLOAD.length(), readData.length(), "Mismatched data length");
            assertEquals(PAYLOAD, readData, "Mismatched read data");
        }
    }

    private void readInOneBuffer(int serverPort) throws Exception {
        outputDebugMessage("readInOneBuffer(port=%d)", serverPort);
        outputDebugMessage("expecting %d bytes", PAYLOAD.length());
        try (Socket s = new Socket()) {
            s.setSoTimeout(2000);
            s.setReceiveBufferSize(65536);
            s.connect(new InetSocketAddress(TEST_LOCALHOST, serverPort));
            Thread.sleep(50L);

            byte buf[] = new byte[PAYLOAD.length()];
            try (InputStream inputStream = s.getInputStream()) {
                int readCount = inputStream.read(buf);
                outputDebugMessage("readInOneBuffer(port=%d) - Got %d bytes from the server", serverPort, readCount);

                String actual = new String(buf, 0, readCount, StandardCharsets.UTF_8);
                assertEquals(PAYLOAD, actual, "Mismatched read data");
            }
        }
    }

    private void readInTwoBuffersWithPause(int serverPort) throws Exception {
        outputDebugMessage("readInTwoBuffersWithPause(port=%d)", serverPort);
        outputDebugMessage("expecting %d bytes", PAYLOAD.length());
        try (Socket s = new Socket()) {
            s.setSoTimeout(2000);
            s.setReceiveBufferSize(65536);
            s.connect(new InetSocketAddress(TEST_LOCALHOST, serverPort));
            Thread.sleep(50L);

            byte b1[] = new byte[PAYLOAD.length() / 2];
            byte b2[] = new byte[PAYLOAD.length()];

            try (InputStream inputStream = s.getInputStream()) {
                int read1 = inputStream.read(b1);
                outputDebugMessage("readInTwoBuffersWithPause(port=%d) - 1st half is %d bytes", serverPort, read1);
                String half1 = new String(b1, 0, read1, StandardCharsets.UTF_8);

                Thread.sleep(50L);
                try {
                    int read2 = inputStream.read(b2);
                    outputDebugMessage("readInTwoBuffersWithPause(port=%d) - 2nd half is %d bytes", serverPort, read2);

                    String half2 = new String(b2, 0, read2, StandardCharsets.UTF_8);
                    assertEquals(PAYLOAD, half1 + half2, "Mismatched read data");
                } catch (IOException e) {
                    log.error("Disconnected ({}) before all data read: {}", e.getClass().getSimpleName(), e.getMessage());
                    throw e;
                }
            }
        }
    }

    protected abstract SshdSocketAddress startRemotePF() throws Exception;

    protected abstract SshdSocketAddress startLocalPF() throws Exception;

    protected abstract void stopRemotePF(SshdSocketAddress bound) throws Exception;

    protected abstract void stopLocalPF(SshdSocketAddress bound) throws Exception;

    protected boolean hasLocalPFStarted(int port) {
        return true;
    }

    protected boolean hasRemotePFStarted(int port) {
        return true;
    }

    /*
     * Connect to test server via port forward and read real quick with one big buffer.
     *
     * PROVIDED AS TEST THAT HAS ALWAYS PASSED
     */
    @Test
    public void remotePortForwardOneBuffer() throws Exception {
        SshdSocketAddress pf = startRemotePF();
        try {
            readInOneBuffer(pf.getPort());
        } finally {
            stopRemotePF(pf);
        }
    }

    /*
     * Connect to test server via port forward and read real quick with one big buffer.
     *
     * THIS IS THE TEST OF SSHD-85
     */
    @Test
    public void remotePortForwardTwoBuffers() throws Exception {
        SshdSocketAddress pf = startRemotePF();
        try {
            readInTwoBuffersWithPause(pf.getPort());
        } finally {
            stopRemotePF(pf);
        }
    }

    @Test
    public void remotePortForwardLoop() throws Exception {
        SshdSocketAddress pf = startRemotePF();
        try {
            readInLoop(pf.getPort());
        } finally {
            stopRemotePF(pf);
        }
    }

    @Test
    public void localPortForwardOneBuffer() throws Exception {
        SshdSocketAddress pf = startLocalPF();
        try {
            readInOneBuffer(pf.getPort());
        } finally {
            stopLocalPF(pf);
        }
    }

    /*
     * Connect to test server via port forward and read with 2 buffers and a pause in between.
     *
     * THIS IS THE TEST OF SSHD-85
     */
    @Test
    public void localPortForwardTwoBuffers() throws Exception {
        SshdSocketAddress pf = startLocalPF();
        try {
            readInTwoBuffersWithPause(pf.getPort());
        } finally {
            stopLocalPF(pf);
        }
    }

    @Test
    public void localPortForwardLoop() throws Exception {
        SshdSocketAddress pf = startLocalPF();
        try {
            readInLoop(pf.getPort());
        } finally {
            stopLocalPF(pf);
        }
    }

    @Test
    public void hasLocalPortForwardingStarted() throws Exception {
        SshdSocketAddress pf = startLocalPF();
        try {
            assertTrue(hasLocalPFStarted(pf.getPort()));
        } finally {
            stopLocalPF(pf);
        }
    }

    @Test
    public void hasRemotePortForwardingStarted() throws Exception {
        SshdSocketAddress pf = startRemotePF();
        try {
            assertTrue(hasRemotePFStarted(pf.getPort()));
        } finally {
            stopRemotePF(pf);
        }
    }

}
