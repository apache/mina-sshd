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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.util.Arrays;
import java.util.stream.Collectors;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.forward.DynamicPortForwardingTracker;
import org.apache.sshd.client.session.forward.ExplicitPortForwardingTracker;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSessionFactory;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.forward.DirectTcpipFactory;
import org.apache.sshd.server.forward.ForwardedTcpipFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Local + dynamic port forwarding test
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class Sshd1033Test extends BaseTestSupport {

    private static final Logger LOGGER = LoggerFactory.getLogger(Sshd1033Test.class);

    private static SshServer sshd;
    private static int sshPort;

    public Sshd1033Test() {
        // Default constructor
    }

    @BeforeClass
    public static void beforeClass() throws Exception {
        sshd = CoreTestSupportUtils.setupTestServer(Sshd1033Test.class);
        sshd.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        sshd.setChannelFactories(Arrays.asList(
                ChannelSessionFactory.INSTANCE,
                DirectTcpipFactory.INSTANCE,
                ForwardedTcpipFactory.INSTANCE));
        sshd.start();
        sshPort = sshd.getPort();
    }

    @AfterClass
    public static void afterClass() throws Exception {
        sshd.stop();
    }

    @Test
    public void testDirect() throws IOException {
        testRemoteURL(null);
    }

    @Test
    public void testLocalAndDynamic() throws IOException {
        doTest(true, true);
    }

    @Test
    public void testLocal() throws IOException {
        doTest(true, false);
    }

    @Test
    public void testDynamic() throws IOException {
        doTest(false, true);
    }

    protected void doTest(boolean testLocal, boolean testDynamic) throws IOException {
        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.setServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE);
            client.start();

            try (ClientSession session = client.connect("temp", "localhost", sshPort).verify().getClientSession()) {
                session.addPasswordIdentity("temp");
                session.auth().verify();

                if (testLocal) {
                    LOGGER.info("================== Local ==================");
                    try (ExplicitPortForwardingTracker localTracker = session.createLocalPortForwardingTracker(
                            new SshdSocketAddress("localhost", 8082),
                            new SshdSocketAddress("test.javastack.org", 80))) {
                        LOGGER.info("LocalPortForwarding: {} -> {}", localTracker.getLocalAddress(),
                                localTracker.getRemoteAddress());
                        SshdSocketAddress localSocketAddress = localTracker.getLocalAddress();
                        assertNotNull(localSocketAddress);
                        Proxy proxy = new Proxy(
                                Proxy.Type.HTTP,
                                new InetSocketAddress(localSocketAddress.getHostName(), localSocketAddress.getPort()));
                        testRemoteURL(proxy);
                    }
                }

                if (testDynamic) {
                    LOGGER.info("================== Dynamic ==================");
                    try (DynamicPortForwardingTracker dynamicTracker = session.createDynamicPortForwardingTracker(
                            new SshdSocketAddress("localhost", 8000))) {
                        LOGGER.info("DynamicPortForwarding: {}", dynamicTracker.getLocalAddress());
                        SshdSocketAddress dynamicSocketAddress = dynamicTracker.getLocalAddress();
                        assertNotNull(dynamicSocketAddress);
                        Proxy proxy = new Proxy(
                                Proxy.Type.SOCKS,
                                new InetSocketAddress(
                                        dynamicSocketAddress.getHostName(), //
                                        dynamicSocketAddress.getPort()));
                        testRemoteURL(proxy);
                    }
                }
            }
        }
    }

    private static void testRemoteURL(final Proxy proxy) throws IOException {
        URL url = new URL("http://test.javastack.org/");
        HttpURLConnection connection = (HttpURLConnection) (proxy != null ? url.openConnection(proxy) : url.openConnection());
        LOGGER.info("Get URL: {}", connection.getURL());
        try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            String result = in.lines().collect(Collectors.joining("\n"));
            LOGGER.info("Response from server: {}", result);
            assertEquals("OK", result);
        }
    }

}
