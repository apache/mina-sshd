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

package org.apache.sshd.client.simple;

import java.io.IOException;
import java.security.KeyPair;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.password.RejectAllPasswordAuthenticator;
import org.apache.sshd.server.auth.pubkey.RejectAllPublickeyAuthenticator;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.client.simple.BaseSimpleClientTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SimpleSessionClientTest extends BaseSimpleClientTestSupport {
    public SimpleSessionClientTest() {
        super();
    }

    @Test
    public void testLoginSessionWithPassword() throws Exception {
        // make sure authentication occurs only for passwords
        sshd.setPublickeyAuthenticator(RejectAllPublickeyAuthenticator.INSTANCE);
        client.start();

        try (ClientSession session = simple.sessionLogin(
                TEST_LOCALHOST, port, getCurrentTestName(), getCurrentTestName())) {
            assertEquals("Mismatched session username", getCurrentTestName(), session.getUsername());
        }
    }

    @Test
    public void testLoginSessionWithIdentity() throws Exception {
        KeyPair identity = CommonTestSupportUtils.getFirstKeyPair(createTestHostKeyProvider());
        AtomicBoolean identityQueried = new AtomicBoolean(false);
        sshd.setPublickeyAuthenticator((username, key, session) -> {
            if (username.equals(getCurrentTestName())) {
                identityQueried.set(true);
                return KeyUtils.compareKeys(identity.getPublic(), key);
            }

            return false;
        });
        // make sure authentication occurs only with public keys
        sshd.setPasswordAuthenticator(RejectAllPasswordAuthenticator.INSTANCE);
        client.start();

        try (ClientSession session = simple.sessionLogin(
                TEST_LOCALHOST, port, getCurrentTestName(), identity)) {
            assertEquals("Mismatched session username",
                    getCurrentTestName(), session.getUsername());
            assertTrue("User identity not queried", identityQueried.get());
        }
    }

    @Test
    public void testConnectionTimeout() throws Exception {
        client.addSessionListener(new SessionListener() {
            @Override
            public void sessionCreated(Session session) {
                try {
                    Thread.sleep(CONNECT_TIMEOUT.toMillis() + 150L);
                } catch (InterruptedException e) {
                    // ignored
                }
            }
        });
        client.start();

        long nanoStart = System.nanoTime();
        try (ClientSession session = simple.sessionLogin(
                TEST_LOCALHOST, port, getCurrentTestName(), getCurrentTestName())) {
            fail("Unexpected connection success");
        } catch (IOException e) {
            long nanoEnd = System.nanoTime();
            long nanoDuration = nanoEnd - nanoStart;
            long nanoTimeout = CONNECT_TIMEOUT.toNanos();
            // we allow the timeout to be shorter than the connect timeout, but no more than 3 times its value
            assertTrue("Expired time (" + nanoDuration + ") too long", nanoDuration < (nanoTimeout * 3L));
        }
    }

    @Test
    public void testAuthenticationTimeout() throws Exception {
        // make sure authentication occurs only for passwords
        sshd.setPublickeyAuthenticator(RejectAllPublickeyAuthenticator.INSTANCE);
        PasswordAuthenticator delegate = Objects.requireNonNull(
                sshd.getPasswordAuthenticator(), "No password authenticator");
        sshd.setPasswordAuthenticator((username, password, session) -> {
            try {
                Thread.sleep(AUTH_TIMEOUT.toMillis() + 150L);
            } catch (InterruptedException e) {
                // ignored
            }
            return delegate.authenticate(username, password, session);
        });
        client.start();

        long nanoStart = System.nanoTime();
        try (ClientSession session = simple.sessionLogin(
                TEST_LOCALHOST, port, getCurrentTestName(), getCurrentTestName())) {
            fail("Unexpected connection success");
        } catch (IOException e) {
            long nanoEnd = System.nanoTime();
            long nanoDuration = nanoEnd - nanoStart;
            long nanoTimeout = AUTH_TIMEOUT.toNanos();
            // we allow the timeout to be shorter than the connect timeout, but no more than 3 times its value
            assertTrue("Expired time (" + nanoDuration + ") too long", nanoDuration < (nanoTimeout * 3L));
        }
    }
}
