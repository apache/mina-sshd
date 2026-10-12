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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.SshException;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.UserAuthPublicKey;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class NoneAuthTest extends BaseTestSupport {

    private static final String USER_NAME = "user";

    private SshServer sshd;
    private SshClient client;
    private int port;

    @BeforeEach
    void setUp() throws Exception {
        sshd = CoreTestSupportUtils.setupTestServer(NoneAuthTest.class);
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestClient(NoneAuthTest.class);
        client.start();
    }

    @AfterEach
    void tearDown() throws Exception {
        if (client != null) {
            client.stop();
        }
        if (sshd != null) {
            sshd.stop(true);
        }
    }

    @Test
    void noneAuthFailsByDefault() throws Exception {
        try (ClientSession session = createClientSession(USER_NAME, client, port)) {
            assertThrows(SshException.class, () -> session.auth().verify(AUTH_TIMEOUT));
        }
    }

    @Test
    void noneAuthSucceedsIfFactorySet() throws Exception {
        sshd.setUserAuthFactories(Collections.singletonList(UserAuthNoneFactory.INSTANCE));
        try (ClientSession session = createClientSession(USER_NAME, client, port)) {
            AuthFuture authed = session.auth().verify(AUTH_TIMEOUT);
            assertTrue(authed.isDone());
            assertTrue(authed.isSuccess());
            assertTrue(session.isAuthenticated());
            assertTrue(session.isOpen());
        }
    }

    @Test
    void noneAuthSucceedsIfAdded() throws Exception {
        List<UserAuthFactory> factories = new ArrayList<>(sshd.getUserAuthFactories());
        factories.add(UserAuthNoneFactory.INSTANCE);
        sshd.setUserAuthFactories(factories);
        try (ClientSession session = createClientSession(USER_NAME, client, port)) {
            AuthFuture authed = session.auth().verify(AUTH_TIMEOUT);
            assertTrue(authed.isDone());
            assertTrue(authed.isSuccess());
            assertTrue(session.isAuthenticated());
            assertTrue(session.isOpen());
        }
    }

    @Test
    void noneAuthSucceedsIfConfigured() throws Exception {
        List<UserAuthFactory> factories = new ArrayList<>(sshd.getUserAuthFactories());
        factories.add(UserAuthNoneFactory.INSTANCE);
        sshd.setUserAuthFactories(factories);
        CoreModuleProperties.AUTH_METHODS.set(sshd, UserAuthNone.NAME);
        try (ClientSession session = createClientSession(USER_NAME, client, port)) {
            AuthFuture authed = session.auth().verify(AUTH_TIMEOUT);
            assertTrue(authed.isDone());
            assertTrue(authed.isSuccess());
            assertTrue(session.isAuthenticated());
            assertTrue(session.isOpen());
        }
    }

    @Test
    void noneAuthFailsIfNotConfigured() throws Exception {
        List<UserAuthFactory> factories = new ArrayList<>(sshd.getUserAuthFactories());
        assertNotNull(NamedResource.findByName(UserAuthPublicKey.NAME, Comparator.naturalOrder(), factories));
        factories.add(UserAuthNoneFactory.INSTANCE);
        sshd.setUserAuthFactories(factories);
        CoreModuleProperties.AUTH_METHODS.set(sshd, UserAuthPublicKey.NAME);
        try (ClientSession session = createClientSession(USER_NAME, client, port)) {
            assertThrows(SshException.class, () -> session.auth().verify(AUTH_TIMEOUT));
        }
    }
}
