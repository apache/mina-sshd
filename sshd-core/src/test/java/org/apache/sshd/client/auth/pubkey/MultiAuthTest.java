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
package org.apache.sshd.client.auth.pubkey;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.auth.password.PasswordAuthenticationReporter;
import org.apache.sshd.client.auth.password.PasswordIdentityProvider;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.AttributeRepository.AttributeKey;
import org.apache.sshd.common.auth.UserAuthMethodFactory;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.AsyncAuthException;
import org.apache.sshd.server.auth.hostbased.RejectAllHostBasedAuthenticator;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class MultiAuthTest extends BaseTestSupport {

    private static final String USER_NAME = "foo";
    private static final String PASSWORD = "pass";

    private SshServer sshd;
    private SshClient client;
    private int port;

    private KeyPair ecKeyUser;
    private KeyPair rsaKeyUser;

    MultiAuthTest() {
        super();
    }

    private static class PubkeyAuth implements PublickeyAuthenticator {

        private static final AttributeKey<Integer> SUCCESSFUL_AUTH_COUNT = new AttributeKey<>();

        private final List<PublicKey> knownKeys;

        PubkeyAuth(PublicKey... keys) {
            knownKeys = GenericUtils.asList(keys);
        }

        @Override
        public boolean authenticate(String username, PublicKey key, ServerSession session) throws AsyncAuthException {
            if (!USER_NAME.equals(username)) {
                return false;
            }
            Integer count = session.getAttribute(SUCCESSFUL_AUTH_COUNT);
            int successfulAuths = count == null ? 0 : count.intValue();
            // Server-side interfaces are poor. We should get the "hasSignature" flag.
            // We know our client will send two auth requests per key (pre-auth without signature, then auth with
            // signature).
            int index = successfulAuths / 2;
            if (index < knownKeys.size()) {
                if (KeyUtils.compareKeys(key, knownKeys.get(index))) {
                    session.setAttribute(SUCCESSFUL_AUTH_COUNT, Integer.valueOf(successfulAuths + 1));
                    return true;
                }
            }
            return false;
        }
    }

    private static KeyPair getKeyPair(String algorithm, int size) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(size);
        return generator.generateKeyPair();
    }

    @BeforeEach
    public void setupClientAndServer() throws Exception {
        sshd = CoreTestSupportUtils.setupTestServer(MultiAuthTest.class);
        sshd.setHostBasedAuthenticator(RejectAllHostBasedAuthenticator.INSTANCE);
        // Generate two user keys
        rsaKeyUser = getKeyPair(KeyUtils.RSA_ALGORITHM, 2048);
        ecKeyUser = getKeyPair(KeyUtils.EC_ALGORITHM, 256);
        sshd.setPublickeyAuthenticator(new PubkeyAuth(rsaKeyUser.getPublic(), ecKeyUser.getPublic()));
        sshd.setPasswordAuthenticator((username, password, session) -> {
            return USER_NAME.equals(username) && PASSWORD.equals(password);
        });
        sshd.start();
        port = sshd.getPort();
        client = CoreTestSupportUtils.setupTestClient(MultiAuthTest.class);
        client.setUserAuthFactoriesNames(UserAuthMethodFactory.PUBLIC_KEY, UserAuthMethodFactory.PASSWORD);
        client.start();
    }

    @AfterEach
    public void teardownClientAndServer() throws Exception {
        if (sshd != null) {
            try {
                sshd.stop(true);
            } finally {
                sshd = null;
            }
        }
        if (client != null) {
            try {
                client.stop();
            } finally {
                client = null;
            }
        }
    }

    @Test
    void testConnect() throws Exception {
        CoreModuleProperties.AUTH_METHODS.set(sshd, "publickey,password,publickey");
        StringBuilder sb = new StringBuilder();
        try (ClientSession session = createClientSession(USER_NAME, client, port)) {
            session.setKeyIdentityProvider(ctx -> {
                List<KeyPair> result = new ArrayList<>();
                result.add(rsaKeyUser);
                result.add(ecKeyUser);
                return result;
            });
            session.setPasswordIdentityProvider(PasswordIdentityProvider.wrapPasswords(PASSWORD));
            session.setPublicKeyAuthenticationReporter(new PubkeyReporter(sb));
            session.setPasswordAuthenticationReporter(new PasswordReporter(sb));
            session.auth().verify(AUTH_TIMEOUT);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage() + '\n' + sb.toString(), e);
        }
        String expected = "publickey TRY RSA rsa-sha2-512\n" //
                          + "publickey PARTIAL RSA\n" //
                          + "password TRY pass\n" //
                          + "password PARTIAL pass\n" //
                          + "publickey TRY EC ecdsa-sha2-nistp256\n" //
                          + "publickey SUCCESS EC\n";
        assertEquals(expected, sb.toString());
    }

    @Test
    void testConnect2() throws Exception {
        CoreModuleProperties.AUTH_METHODS.set(sshd, "publickey,publickey");
        StringBuilder sb = new StringBuilder();
        try (ClientSession session = createClientSession(USER_NAME, client, port)) {
            session.setKeyIdentityProvider(ctx -> {
                List<KeyPair> result = new ArrayList<>();
                result.add(rsaKeyUser);
                result.add(ecKeyUser);
                return result;
            });
            session.setPublicKeyAuthenticationReporter(new PubkeyReporter(sb));
            session.setPasswordAuthenticationReporter(new PasswordReporter(sb));
            session.auth().verify(AUTH_TIMEOUT);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage() + '\n' + sb.toString(), e);
        }
        String expected = "publickey TRY RSA rsa-sha2-512\n" //
                          + "publickey PARTIAL RSA\n" //
                          + "publickey TRY EC ecdsa-sha2-nistp256\n" //
                          + "publickey SUCCESS EC\n";
        assertEquals(expected, sb.toString());
    }

    @Test
    void testConnect3() throws Exception {
        CoreModuleProperties.AUTH_METHODS.set(sshd, "publickey password");
        StringBuilder sb = new StringBuilder();
        try (ClientSession session = createClientSession(USER_NAME, client, port)) {
            session.setKeyIdentityProvider(ctx -> {
                List<KeyPair> result = new ArrayList<>();
                result.add(rsaKeyUser);
                result.add(ecKeyUser);
                return result;
            });
            session.setPublicKeyAuthenticationReporter(new PubkeyReporter(sb));
            session.setPasswordAuthenticationReporter(new PasswordReporter(sb));
            session.auth().verify(AUTH_TIMEOUT);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage() + '\n' + sb.toString(), e);
        }
        String expected = "publickey TRY RSA rsa-sha2-512\n" //
                          + "publickey SUCCESS RSA\n";
        assertEquals(expected, sb.toString());
    }

    @Test
    void testConnect4() throws Exception {
        CoreModuleProperties.AUTH_METHODS.set(sshd, "password,publickey");
        StringBuilder sb = new StringBuilder();
        try (ClientSession session = createClientSession(USER_NAME, client, port)) {
            session.setKeyIdentityProvider(ctx -> {
                List<KeyPair> result = new ArrayList<>();
                result.add(rsaKeyUser);
                result.add(ecKeyUser);
                return result;
            });
            session.setPasswordIdentityProvider(PasswordIdentityProvider.wrapPasswords(PASSWORD));
            session.setPublicKeyAuthenticationReporter(new PubkeyReporter(sb));
            session.setPasswordAuthenticationReporter(new PasswordReporter(sb));
            session.auth().verify(AUTH_TIMEOUT);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage() + '\n' + sb.toString(), e);
        }
        String expected = "password TRY pass\n" //
                          + "password PARTIAL pass\n" //
                          + "publickey TRY RSA rsa-sha2-512\n" //
                          + "publickey SUCCESS RSA\n";
        assertEquals(expected, sb.toString());
    }

    @Test
    void testConnect5() throws Exception {
        CoreModuleProperties.AUTH_METHODS.set(sshd, "password,publickey,publickey");
        StringBuilder sb = new StringBuilder();
        try (ClientSession session = createClientSession(USER_NAME, client, port)) {
            session.setKeyIdentityProvider(ctx -> {
                List<KeyPair> result = new ArrayList<>();
                result.add(rsaKeyUser);
                result.add(ecKeyUser);
                return result;
            });
            session.setPasswordIdentityProvider(PasswordIdentityProvider.wrapPasswords(PASSWORD));
            session.setPublicKeyAuthenticationReporter(new PubkeyReporter(sb));
            session.setPasswordAuthenticationReporter(new PasswordReporter(sb));
            session.auth().verify(AUTH_TIMEOUT);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage() + '\n' + sb.toString(), e);
        }
        String expected = "password TRY pass\n" //
                          + "password PARTIAL pass\n" //
                          + "publickey TRY RSA rsa-sha2-512\n" //
                          + "publickey PARTIAL RSA\n" //
                          + "publickey TRY EC ecdsa-sha2-nistp256\n" //
                          + "publickey SUCCESS EC\n";
        assertEquals(expected, sb.toString());
    }

    private static class PubkeyReporter implements PublicKeyAuthenticationReporter {

        private final StringBuilder out;

        PubkeyReporter(StringBuilder sink) {
            out = sink;
        }

        @Override
        public void signalAuthenticationAttempt(ClientSession session, String service, KeyPair identity, String signature)
                throws Exception {
            out.append("publickey TRY ").append(identity == null ? "null" : identity.getPublic().getAlgorithm()).append(' ')
                    .append(signature == null ? "null" : signature).append('\n');
        }

        @Override
        public void signalAuthenticationSuccess(ClientSession session, String service, KeyPair identity) throws Exception {
            out.append("publickey SUCCESS ").append(identity == null ? "null" : identity.getPublic().getAlgorithm())
                    .append('\n');
        }

        @Override
        public void signalAuthenticationFailure(
                ClientSession session, String service, KeyPair identity, boolean partial,
                List<String> serverMethods) throws Exception {
            out.append("publickey ").append(partial ? "PARTIAL " : "FAILURE ")
                    .append(identity == null ? "null" : identity.getPublic().getAlgorithm()).append('\n');
        }
    }

    private static class PasswordReporter implements PasswordAuthenticationReporter {

        private final StringBuilder out;

        PasswordReporter(StringBuilder sink) {
            out = sink;
        }

        @Override
        public void signalAuthenticationAttempt(
                ClientSession session, String service, String oldPassword, boolean modified,
                String newPassword) throws Exception {
            out.append("password TRY " + oldPassword).append('\n');
        }

        @Override
        public void signalAuthenticationSuccess(ClientSession session, String service, String password) throws Exception {
            out.append("password SUCCESS " + password).append('\n');
        }

        @Override
        public void signalAuthenticationFailure(
                ClientSession session, String service, String password, boolean partial,
                List<String> serverMethods) throws Exception {
            out.append("password ").append(partial ? "PARTIAL " : "FAILURE ").append(password == null ? "null" : password)
                    .append('\n');
        }
    }
}
