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
package org.apache.sshd.server.auth;

import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.stream.Stream;

import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.config.keys.u2f.SkEcdsaPublicKey;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.server.auth.pubkey.AuthorizedKeyEntriesPublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;

@Tag("NoIoTestCase")
class AuthorizedKeyEntriesPublickeyAuthenticatorTest extends BaseTestSupport {

    private static Stream<Arguments> options() {
        return Stream.of(Arguments.of("", ""), //
                Arguments.of("no-touch-required", ""), //
                Arguments.of("verify-required", ""), //
                Arguments.of("no-touch-required", "verify-required") //
        );
    }

    @ParameterizedTest(name = "match {0} {1}")
    @MethodSource("options")
    void testMatch(String first, String second) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(256);
        KeyPair pair = gen.generateKeyPair();
        ECPublicKey key = ValidateUtils.checkInstanceOf(pair.getPublic(), ECPublicKey.class, "Expected an EC key");
        SkEcdsaPublicKey pubKey = new SkEcdsaPublicKey("ssh", false, false, key);
        String line = first;
        if (!second.isEmpty()) {
            line += ',' + second;
        }
        if (!line.isEmpty()) {
            line = line + ' ';
        }
        line += PublicKeyEntry.toString(pubKey);
        AuthorizedKeyEntry entry = AuthorizedKeyEntry.parseAuthorizedKeyEntry(line);
        AuthorizedKeyEntriesPublickeyAuthenticator auth = new AuthorizedKeyEntriesPublickeyAuthenticator("test", null,
                Collections.singletonList(entry), PublicKeyEntryResolver.FAILING);
        assertTrue(auth.authenticate("user", pubKey, null));
    }

    @Test
    void fromAllowsMatchingAddress() throws Exception {
        KeyPair pair = generateKeyPair();
        ServerSession session = session(new InetSocketAddress("127.0.0.1", 12345));

        assertTrue(authenticate("from=\"127.0.0.1\"", pair, session));
    }

    @Test
    void fromRejectsDifferentAddress() throws Exception {
        KeyPair pair = generateKeyPair();
        ServerSession session = session(new InetSocketAddress("203.0.113.10", 12345));

        assertFalse(authenticate("from=\"127.0.0.1\"", pair, session));
    }

    @Test
    void fromAllowsMatchingCidr() throws Exception {
        KeyPair pair = generateKeyPair();
        ServerSession session = session(new InetSocketAddress("192.0.2.25", 12345));

        assertTrue(authenticate("from=\"192.0.2.0/24\"", pair, session));
    }

    @Test
    void fromRejectsNegatedAddress() throws Exception {
        KeyPair pair = generateKeyPair();
        ServerSession session = session(new InetSocketAddress("203.0.113.10", 12345));

        assertFalse(authenticate("from=\"*,!203.0.113.10\"", pair, session));
    }

    @Test
    void fromRejectsInvalidPattern() throws Exception {
        KeyPair pair = generateKeyPair();
        ServerSession session = session(new InetSocketAddress("203.0.113.10", 12345));

        assertFalse(authenticate("from=\"203.0.113.0/33\"", pair, session));
    }

    @Test
    void expiryTimeAllowsFutureTime() throws Exception {
        KeyPair pair = generateKeyPair();

        assertTrue(authenticate("expiry-time=\"29991231235959Z\"", pair, null));
    }

    @Test
    void expiryTimeRejectsPastTime() throws Exception {
        KeyPair pair = generateKeyPair();

        assertFalse(authenticate("expiry-time=\"19700101000000Z\"", pair, null));
    }

    private static boolean authenticate(String options, KeyPair pair, ServerSession session) throws Exception {
        String line = options;
        if (!line.isEmpty()) {
            line += ' ';
        }
        line += PublicKeyEntry.toString(pair.getPublic());
        AuthorizedKeyEntry entry = AuthorizedKeyEntry.parseAuthorizedKeyEntry(line);
        AuthorizedKeyEntriesPublickeyAuthenticator auth = new AuthorizedKeyEntriesPublickeyAuthenticator("test", session,
                Collections.singletonList(entry), PublicKeyEntryResolver.FAILING);
        return auth.authenticate("user", pair.getPublic(), session);
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(256);
        return gen.generateKeyPair();
    }

    private static ServerSession session(InetSocketAddress remote) {
        ServerSession session = Mockito.mock(ServerSession.class);
        Mockito.when(session.getClientAddress()).thenReturn(remote);
        Mockito.when(session.getRemoteAddress()).thenReturn(remote);
        return session;
    }
}
