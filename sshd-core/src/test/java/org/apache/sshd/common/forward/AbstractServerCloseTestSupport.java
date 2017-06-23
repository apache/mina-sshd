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
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousServerSocketChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Port forwarding tests
 */
public abstract class AbstractServerCloseTestSupport extends BaseTestSupport {
    private static final Logger log = LoggerFactory.getLogger(AbstractServerCloseTestSupport.class);
    private static final String PAYLOAD = String.join("", Collections.nCopies(200, "This is significantly longer Test Data."));

    protected int testServerPort;
    private AsynchronousServerSocketChannel testServerSock;

    protected AbstractServerCloseTestSupport() {
        super();
    }

    /*
     * Start a server to forward to.
     *
     * This server sends PAYLOAD and then closes.
     */
    @Before
    public void startTestServer() throws Exception {
        InetSocketAddress sockAddr = new InetSocketAddress(TEST_LOCALHOST, 0);
        testServerSock = AsynchronousServerSocketChannel.open().bind(sockAddr);
        testServerPort = ((InetSocketAddress) testServerSock.getLocalAddress()).getPort();
        // Accept a connection
        testServerSock.accept(testServerSock,
                new CompletionHandler<AsynchronousSocketChannel, AsynchronousServerSocketChannel>() {
                    @Override
                    public void completed(AsynchronousSocketChannel sockChannel,
                            AsynchronousServerSocketChannel serverSock) {
                        // a connection is accepted, start to accept next
                        // connection
                        serverSock.accept(serverSock, this);
                        @SuppressWarnings("synthetic-access")
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
                                            System.err.println("Failed to close");
                                        }
                                    }

                                    @Override
                                    public void failed(Throwable exc, AsynchronousSocketChannel channel) {
                                        System.err.println("Failed to write message to client");
                                    }
                                });
                    }

                    @Override
                    public void failed(Throwable exc, AsynchronousServerSocketChannel serverSock) {
                        System.out.println("Failed to accept a connection");
                    }
                });
    }

    @After
    public void stopTestServer() throws Exception {
        testServerSock.close();
    }

    private void readInLoop(int serverPort) throws Exception {
        log.debug("Connecting to {}", serverPort);
        StringBuilder sb = new StringBuilder();
        try (Socket s = new Socket(TEST_LOCALHOST, serverPort)) {
            s.setSoTimeout(300);

            try(InputStream inputStream = s.getInputStream()) {
                byte b[] = new byte[PAYLOAD.length() / 10];
                while (true) {
                    int read = inputStream.read(b);
                    if (read == -1) {
                        break;
                    }
                    sb.append(new String(b, 0, read, StandardCharsets.UTF_8));
                    Thread.sleep(25L);
                }
            }
        } catch (IOException e) {
            String readData = sb.toString();
            assertEquals("Mismatched data length", PAYLOAD.length(), readData.length());
            assertEquals("Mismatched read data", PAYLOAD, readData);
        }
    }

    private void readInOneBuffer(int serverPort) throws Exception {
        log.debug("Connecting to {}", serverPort);
        try (Socket s = new Socket(TEST_LOCALHOST, serverPort)) {
            s.setSoTimeout(300);

            byte buf[] = new byte[PAYLOAD.length()];
            try(InputStream inputStream = s.getInputStream()) {
                int readCount = inputStream.read(buf);
                String actual = new String(buf, 0, readCount, StandardCharsets.UTF_8);
                log.info("Got {} bytes from the server: {}", readCount, actual);
                assertEquals("Mismatched read data", PAYLOAD, actual);
            }
        }
    }

    private void readInTwoBuffersWithPause(int serverPort) throws Exception {
        log.debug("Connecting to {}", serverPort);
        try (Socket s = new Socket(TEST_LOCALHOST, serverPort)) {
            s.setSoTimeout(300);
            byte b1[] = new byte[PAYLOAD.length() / 2];
            byte b2[] = new byte[PAYLOAD.length()];

            try(InputStream inputStream = s.getInputStream()) {
                int read1 = inputStream.read(b1);
                String half1 = new String(b1, 0, read1, StandardCharsets.UTF_8);
                log.info("Got {} bytes from the server: {}", read1, half1);

                Thread.sleep(50L);

                try {
                    int read2 = inputStream.read(b2);
                    String half2 = new String(b2, 0, read2, StandardCharsets.UTF_8);
                    log.info("Got {} bytes from the server: {}", read2, half2);
                    assertEquals("Mismatched read data", PAYLOAD, half1 + half2);
                } catch (SocketException e) {
                    log.error("Disconnected before all data read: ", e);
                    fail("Caught error from socket durning second read" + e.getMessage());
                }
            }
        }
    }

    protected abstract int startRemotePF() throws Exception;

    protected abstract int startLocalPF() throws Exception;

    /*
     * Connect to test server via port forward and read real quick with one big
     * buffer.
     *
     * PROVIDED AS TEST THAT HAS ALWAYS PASSED
     */
    @Test
    public void testRemotePortForwardOneBuffer() throws Exception {
        readInOneBuffer(startRemotePF());
    }

    /*
     * Connect to test server via port forward and read real quick with one big
     * buffer.
     *
     * THIS IS THE TEST OF SSHD-85
     */
    @Test
    public void testRemotePortForwardTwoBuffers() throws Exception {
        readInTwoBuffersWithPause(startRemotePF());
    }

    @Test
    public void testRemotePortForwardLoop() throws Exception {
        readInLoop(startRemotePF());
    }

    @Test
    public void testLocalPortForwardOneBuffer() throws Exception {
        readInOneBuffer(startLocalPF());
    }

    /*
     * Connect to test server via port forward and read with 2 buffers and a
     * pause in between.
     *
     * THIS IS THE TEST OF SSHD-85
     */
    @Test
    public void testLocalPortForwardTwoBuffers() throws Exception {
        readInTwoBuffersWithPause(startLocalPF());
    }

    @Test
    public void testLocalPortForwardLoop() throws Exception {
        readInLoop(startLocalPF());
    }
}