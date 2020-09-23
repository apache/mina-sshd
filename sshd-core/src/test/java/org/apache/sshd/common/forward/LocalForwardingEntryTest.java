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
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Proxy;
import java.net.SocketException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.forward.ExplicitPortForwardingTracker;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class LocalForwardingEntryTest extends BaseTestSupport {
    public LocalForwardingEntryTest() {
        super();
    }

    @Test // NOTE: this also checks indirectly SshSocketAddress host comparison case-insensitive
    public void testCaseInsensitiveMatching() {
        LocalForwardingEntry expected = new LocalForwardingEntry(getClass().getSimpleName(), getCurrentTestName(), 7365);
        String hostname = expected.getHostName();
        String alias = expected.getAlias();
        int port = expected.getPort();
        List<LocalForwardingEntry> entries = IntStream.rangeClosed(1, 4)
                .mapToObj(seed -> new LocalForwardingEntry(hostname + "-" + seed, alias + "-" + seed, port + seed))
                .collect(Collectors.toCollection(ArrayList::new));
        entries.add(expected);

        for (String host : new String[] { hostname, alias }) {
            for (int index = 1; index <= 4; index++) {
                Collections.shuffle(entries);

                LocalForwardingEntry actual = LocalForwardingEntry.findMatchingEntry(host, port, entries);
                assertSame("Mismatched result for host=" + host, expected, actual);

                host = shuffleCase(host);
            }
        }
    }

    @Ignore("enable to test SSHD-1066: Support multiple local interfaces in PortForwarding")
    @Test
    public void testLocalBinding() throws Throwable {
        try (SshServer server = setupTestServer()) {
            server.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
            server.start();
            InetSocketAddress addr = (InetSocketAddress) server.getBoundAddresses().iterator().next();

            try (SshClient client = SshClient.setUpDefaultClient()) {
                client.setServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE);
                client.start();
                try (ClientSession session = client.connect("test", addr)
                        .verify(CONNECT_TIMEOUT).getClientSession()) {
                    session.addPasswordIdentity("test");
                    session.auth().verify(AUTH_TIMEOUT);

                    List<String> allAddresses = getHostAddresses();
                    List<ExplicitPortForwardingTracker> trackers = new ArrayList<>();
                    for (String host : allAddresses) {
                        ExplicitPortForwardingTracker tracker = session.createLocalPortForwardingTracker(
                                new SshdSocketAddress(host, 8080),
                                new SshdSocketAddress("test.javastack.org", 80));
                        testRemoteURL(new Proxy(Proxy.Type.HTTP, tracker.getBoundAddress().toInetSocketAddress()),
                                "http://test.javastack.org/");
                        trackers.add(tracker);
                    }
                    IoUtils.closeQuietly(trackers);
                }
            }
        }
    }

    static List<String> getHostAddresses() throws SocketException {
        List<String> addresses = new ArrayList<>();
        Enumeration<NetworkInterface> eni = NetworkInterface.getNetworkInterfaces();
        while (eni.hasMoreElements()) {
            Enumeration<InetAddress> eia = eni.nextElement().getInetAddresses();
            while (eia.hasMoreElements()) {
                InetAddress ia = eia.nextElement();
                if (ia instanceof Inet4Address) {
                    addresses.add(ia.getHostAddress());
                }
            }
        }
        return addresses;
    }

    static void testRemoteURL(final Proxy proxy, final String url) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection(proxy);
        connection.setConnectTimeout((int) DEFAULT_TIMEOUT.toMillis());
        connection.setReadTimeout((int) DEFAULT_TIMEOUT.toMillis());
        String result;
        try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            result = in.lines().collect(Collectors.joining(System.lineSeparator()));
        }
        assertEquals("Unexpected server response", "OK", result);
    }

}
