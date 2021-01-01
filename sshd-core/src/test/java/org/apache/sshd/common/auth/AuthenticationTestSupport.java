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

package org.apache.sshd.common.auth;

import java.io.IOException;
import java.security.KeyPair;

import org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.After;
import org.junit.Before;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AuthenticationTestSupport extends BaseTestSupport {
    protected static final AttributeRepository.AttributeKey<Boolean> PASSWORD_ATTR = new AttributeRepository.AttributeKey<>();

    protected SshServer sshd;
    protected int port;

    protected AuthenticationTestSupport() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
        sshd.start();
        port = sshd.getPort();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
    }

    protected static void assertAuthenticationResult(String message, AuthFuture future, boolean expected) throws IOException {
        assertTrue(message + ": failed to get result on time", future.await(AUTH_TIMEOUT));
        assertEquals(message + ": mismatched authentication result", expected, future.isSuccess());
    }

    protected static AuthFuture authPassword(ClientSession s, String user, String pswd) throws IOException {
        s.setUsername(user);
        s.addPasswordIdentity(pswd);
        return s.auth();
    }

    protected static AuthFuture authInteractive(ClientSession s, String user, String pswd) throws IOException {
        s.setUsername(user);
        final String[] response = { pswd };
        s.setUserInteraction(new UserInteraction() {
            @Override
            public boolean isInteractionAllowed(ClientSession session) {
                return true;
            }

            @Override
            public String[] interactive(
                    ClientSession session, String name, String instruction,
                    String lang, String[] prompt, boolean[] echo) {
                assertSame("Mismatched session instance", s, session);
                assertEquals("Mismatched prompt size", 1, GenericUtils.length(prompt));
                assertTrue("Mismatched prompt: " + prompt[0], prompt[0].toLowerCase().contains("password"));
                return response;
            }

            @Override
            public String getUpdatedPassword(ClientSession session, String prompt, String lang) {
                throw new UnsupportedOperationException("Unexpected password update request");
            }
        });
        return s.auth();
    }

    protected static AuthFuture authPublicKey(ClientSession s, String user, KeyPair pair) throws IOException {
        s.setUsername(user);
        s.addPublicKeyIdentity(pair);
        return s.auth();
    }
}
