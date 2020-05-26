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

package org.apache.sshd.server;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.keyprovider.HostKeyCertificateProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.auth.BuiltinUserAuthFactories;
import org.apache.sshd.server.auth.UserAuthFactory;
import org.apache.sshd.server.auth.gss.GSSAuthenticator;
import org.apache.sshd.server.auth.hostbased.HostBasedAuthenticator;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class ServerAuthenticationManagerTest extends BaseTestSupport {
    public ServerAuthenticationManagerTest() {
        super();
    }

    @Test
    public void testDefaultUserAuthFactoriesMethods() {
        AtomicReference<List<UserAuthFactory>> factoriesHolder = new AtomicReference<>();
        @SuppressWarnings("checkstyle:anoninnerlength")
        ServerAuthenticationManager manager = new ServerAuthenticationManager() {
            @Override
            public List<UserAuthFactory> getUserAuthFactories() {
                return factoriesHolder.get();
            }

            @Override
            public void setUserAuthFactories(List<UserAuthFactory> userAuthFactories) {
                assertNull("Unexpected multiple invocation", factoriesHolder.getAndSet(userAuthFactories));
            }

            @Override
            public PasswordAuthenticator getPasswordAuthenticator() {
                return null;
            }

            @Override
            public void setPasswordAuthenticator(PasswordAuthenticator passwordAuthenticator) {
                throw new UnsupportedOperationException("setPasswordAuthenticator(" + passwordAuthenticator + ")");
            }

            @Override
            public PublickeyAuthenticator getPublickeyAuthenticator() {
                return null;
            }

            @Override
            public void setPublickeyAuthenticator(PublickeyAuthenticator publickeyAuthenticator) {
                throw new UnsupportedOperationException("setPublickeyAuthenticator(" + publickeyAuthenticator + ")");
            }

            @Override
            public KeyboardInteractiveAuthenticator getKeyboardInteractiveAuthenticator() {
                return null;
            }

            @Override
            public void setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator interactiveAuthenticator) {
                throw new UnsupportedOperationException(
                        "setKeyboardInteractiveAuthenticator(" + interactiveAuthenticator + ")");
            }

            @Override
            public GSSAuthenticator getGSSAuthenticator() {
                return null;
            }

            @Override
            public void setGSSAuthenticator(GSSAuthenticator gssAuthenticator) {
                throw new UnsupportedOperationException("setGSSAuthenticator(" + gssAuthenticator + ")");
            }

            @Override
            public HostBasedAuthenticator getHostBasedAuthenticator() {
                return null;
            }

            @Override
            public void setHostBasedAuthenticator(HostBasedAuthenticator hostBasedAuthenticator) {
                throw new UnsupportedOperationException("setHostBasedAuthenticator(" + hostBasedAuthenticator + ")");
            }

            @Override
            public KeyPairProvider getKeyPairProvider() {
                return null;
            }

            @Override
            public void setKeyPairProvider(KeyPairProvider keyPairProvider) {
                throw new UnsupportedOperationException("setKeyPairProvider(" + keyPairProvider + ")");
            }

            @Override
            public HostKeyCertificateProvider getHostKeyCertificateProvider() {
                return null;
            }

            @Override
            public void setHostKeyCertificateProvider(HostKeyCertificateProvider provider) {
                throw new UnsupportedOperationException("setHostKeyCertificateProvider(" + provider + ")");
            }
        };
        assertEquals("Mismatched initial factories list", "", manager.getUserAuthFactoriesNameList());

        String expected = NamedResource.getNames(BuiltinUserAuthFactories.VALUES);
        manager.setUserAuthFactoriesNameList(expected);
        assertEquals("Mismatched updated factories names", expected, manager.getUserAuthFactoriesNameList());

        List<UserAuthFactory> factories = factoriesHolder.get();
        assertEquals("Mismatched factories count",
                BuiltinUserAuthFactories.VALUES.size(), GenericUtils.size(factories));
        for (BuiltinUserAuthFactories f : BuiltinUserAuthFactories.VALUES) {
            assertTrue("Missing factory=" + f.name(), factories.contains(f.create()));
        }
    }
}
