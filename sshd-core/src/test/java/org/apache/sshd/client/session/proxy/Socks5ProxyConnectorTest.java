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
package org.apache.sshd.client.session.proxy;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;

import org.apache.sshd.client.proxy.ProxyData;
import org.apache.sshd.common.forward.SocksConstants.Socks5;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Basic tests for accumulating the SOCKS connection reply.
 */
@Tag("NoIoTestCase")
class Socks5ProxyConnectorTest extends JUnitTestSupport {

    @Test
    void splitConnectionReply() throws Exception {
        byte[] chunk1 = new byte[] { 5 }; // Socks version
        byte[] chunk2 = new byte[] { Socks5.REPLY_SUCCESS, 0 };
        byte[] chunk3 = new byte[] { Socks5.ADDRESS_IPV4, 1, 2, 3 };
        byte[] chunk4 = new byte[] {
                4, 0, 100, (byte) 'S', (byte) 'S', (byte) 'H', (byte) '-', (byte) '2', (byte) '.',
                (byte) '0', (byte) '-', (byte) 'X', (byte) '\n' };
        InetSocketAddress unused = new InetSocketAddress(InetAddress.getLocalHost(), 2000);
        ProxyData proxy = new ProxyData(new Proxy(Proxy.Type.SOCKS, unused), "user", "pass".toCharArray());
        try (Socks5ProxyConnector connector = new Socks5ProxyConnector(proxy, unused, b -> null, a -> null)) {
            assertNull(connector.receiveConnectReply(new ByteArrayBuffer(chunk1)));
            assertNull(connector.receiveConnectReply(new ByteArrayBuffer(chunk2)));
            assertNull(connector.receiveConnectReply(new ByteArrayBuffer(chunk3)));
            Buffer rest = connector.receiveConnectReply(new ByteArrayBuffer(chunk4));
            assertTrue(connector.isDone());
            String ident = new String(rest.array(), rest.rpos(), rest.available(), StandardCharsets.US_ASCII);
            assertEquals("SSH-2.0-X\n", ident);
        }
    }

}
