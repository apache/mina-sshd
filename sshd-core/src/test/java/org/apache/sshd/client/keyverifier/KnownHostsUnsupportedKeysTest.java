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
package org.apache.sshd.client.keyverifier;

import java.net.SocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.config.hosts.KnownHostEntry;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.config.keys.UnsupportedSshPublicKey;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

@Tag("NoIoTestCase")
class KnownHostsUnsupportedKeysTest extends JUnitTestSupport {

    @TempDir
    private Path tmp;

    private boolean invokeVerifier(ServerKeyVerifier verifier, SocketAddress hostIdentity, PublicKey serverKey) {
        ClientSession session = Mockito.mock(ClientSession.class);
        Mockito.when(session.getConnectAddress()).thenReturn(hostIdentity);
        Mockito.when(session.toString()).thenReturn(getCurrentTestName() + "[" + hostIdentity + "]");
        return verifier.verifyServerKey(session, hostIdentity, serverKey);
    }

    @Test
    void unknownExistingKey() throws Exception {
        Path knownHosts = tmp.resolve("known_hosts");
        List<String> lines = new ArrayList<>();
        lines.add("[127.0.0.1]:2222 ssh-ed448 AAAAC3NzaC1lZDI1NTE5AAAAIPu6ntmyfSOkqLl3qPxD5XxwW7OONwwSG3KO+TGn+PFu");
        lines.add(
                "[127.0.0.1]:2222 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCbZVVpqEHGLNWMqMeyU1VbWb91XteoamVcgpy4yxNVbZffb5IDdbo1ons/y9KAhcub6LZeLrvXzVUZbXCZiUkg=");
        Files.write(knownHosts, lines);
        KnownHostsServerKeyVerifier verifier = new KnownHostsServerKeyVerifier(RejectAllServerKeyVerifier.INSTANCE, knownHosts);
        KnownHostEntry knownHost = KnownHostEntry.parseKnownHostEntry(lines.get(1));
        AuthorizedKeyEntry keyEntry = knownHost.getKeyEntry();
        assertNotNull(keyEntry);
        PublicKey key = keyEntry.resolvePublicKey(null, PublicKeyEntryResolver.FAILING);
        assertTrue(invokeVerifier(verifier, new SshdSocketAddress("127.0.0.1", 2222), key));
    }

    @Test
    void unknownNewKey() throws Exception {
        KeyPair kp = CommonTestSupportUtils.generateKeyPair(KeyUtils.RSA_ALGORITHM, 1024);
        PublicKey newKey = kp.getPublic();
        Path knownHosts = tmp.resolve("known_hosts");
        List<String> lines = new ArrayList<>();
        lines.add("[127.0.0.1]:2222 ssh-ed448 AAAAC3NzaC1lZDI1NTE5AAAAIPu6ntmyfSOkqLl3qPxD5XxwW7OONwwSG3KO+TGn+PFu");
        Files.write(knownHosts, lines);
        AtomicInteger numberOfCalls = new AtomicInteger();
        KnownHostsServerKeyVerifier verifier = new KnownHostsServerKeyVerifier(RejectAllServerKeyVerifier.INSTANCE,
                knownHosts) {
            @Override
            public boolean acceptModifiedServerKey(
                    ClientSession clientSession, SocketAddress remoteAddress,
                    KnownHostEntry entry, PublicKey expected, PublicKey actual) throws Exception {
                numberOfCalls.incrementAndGet();
                assertSame(newKey, actual, "Mismatched actual key for " + remoteAddress);
                assertTrue(expected instanceof UnsupportedSshPublicKey);
                String fingerprint = KeyUtils.getFingerPrint(expected);
                assertNotNull(fingerprint);
                assertTrue(fingerprint.length() > 0);
                return true;
            }
        };
        assertTrue(invokeVerifier(verifier, new SshdSocketAddress("127.0.0.1", 2222), newKey));
        assertEquals(1, numberOfCalls.get());
        // Load the file again. We should have two entries now, and the second one should be our newKey
        List<KnownHostEntry> newEntries = KnownHostEntry.readKnownHostEntries(knownHosts);
        assertNotNull(newEntries);
        assertEquals(2, newEntries.size());
        KnownHostEntry knownHost = newEntries.get(1);
        AuthorizedKeyEntry keyEntry = knownHost.getKeyEntry();
        assertNotNull(keyEntry);
        PublicKey key = keyEntry.resolvePublicKey(null, PublicKeyEntryResolver.FAILING);
        assertTrue(KeyUtils.compareKeys(newKey, key));
    }
}
