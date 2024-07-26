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
package org.apache.sshd.util.test;

import java.io.IOException;
import java.time.Duration;
import java.util.Collection;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.helpers.AbstractFactoryManager;
import org.apache.sshd.common.io.BuiltinIoServiceFactoryFactories;
import org.apache.sshd.common.io.DefaultIoServiceFactoryFactory;
import org.apache.sshd.common.io.IoServiceFactoryFactory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.SshServer;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestWatcher;

/**
 * Helper used as base class for all test classes
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@ExtendWith(BaseTestSupport.CustomTestWatcher.class)
public abstract class BaseTestSupport extends JUnitTestSupport {
    // can be used to override the 'localhost' with an address other than 127.0.0.1 in case it is required
    public static final String TEST_LOCALHOST
            = System.getProperty("org.apache.sshd.test.localhost", SshdSocketAddress.LOCALHOST_IPV4);

    public static final Duration CONNECT_TIMEOUT = CoreTestSupportUtils.getTimeout("connect", Duration.ofSeconds(10));
    public static final Duration AUTH_TIMEOUT = CoreTestSupportUtils.getTimeout("auth", Duration.ofSeconds(8));
    public static final Duration OPEN_TIMEOUT = CoreTestSupportUtils.getTimeout("open", Duration.ofSeconds(9));
    public static final Duration DEFAULT_TIMEOUT = CoreTestSupportUtils.getTimeout("default", Duration.ofSeconds(5));
    public static final Duration CLOSE_TIMEOUT = CoreTestSupportUtils.getTimeout("close", Duration.ofSeconds(15));

    static class CustomTestWatcher implements TestWatcher, BeforeEachCallback, AfterEachCallback {
        // TODO consider using a ThreadLocal storage for the start time - provided
        // the code is assured to call starting/finished on the same thread
        private long startTime;

        @Override
        public void beforeEach(ExtensionContext context) {
            System.out.append(System.lineSeparator())
                    .append("Starting ")
                    .append(context.getDisplayName())
                    //.append(description.getClassName())
                    //.append(':').append(description.getMethodName())
                    .println("...");
            try {
                IoServiceFactoryFactory ioProvider = getIoServiceProvider();
                System.out.println("Using default provider: " + ioProvider.getClass().getName());
            } catch (Throwable t) {
                // Ignore
            }
            System.out.println();
            startTime = System.currentTimeMillis();
        }

        @Override
        public void afterEach(ExtensionContext context) {
            long duration = System.currentTimeMillis() - startTime;
            System.out.append(System.lineSeparator())
                    .append("Finished ")
                    .append(context.getDisplayName())
                    //.append(description.getClassName())
                    //.append(':').append(description.getMethodName())
                    .append(" in ").append(Long.toString(duration))
                    .println(" ms");
        }
    };

    protected BaseTestSupport() {
        super();
    }

    protected SshServer setupTestServer() {
        return CoreTestSupportUtils.setupTestServer(getClass());
    }

    protected SshServer setupTestFullSupportServer() {
        return CoreTestSupportUtils.setupTestFullSupportServer(setupTestServer());
    }

    protected SshClient setupTestClient() {
        return CoreTestSupportUtils.setupTestClient(getClass());
    }

    protected SshClient setupTestFullSupportClient() {
        return CoreTestSupportUtils.setupTestFullSupportClient(setupTestClient());
    }

    protected void assumeNotIoServiceProvider(
            Collection<BuiltinIoServiceFactoryFactories> excluded) {
        assumeNotIoServiceProvider(getCurrentTestName(), excluded);
    }

    protected ClientSession createClientSession(SshClient client, int port) throws IOException {
        return createClientSession(getCurrentTestName(), client, port);
    }

    protected ClientSession createAuthenticatedClientSession(SshClient client, int port) throws IOException {
        return createAuthenticatedClientSession(getCurrentTestName(), client, port);
    }

    public static ClientSession createClientSession(String username, SshClient client, int port) throws IOException {
        return client.connect(username, TEST_LOCALHOST, port)
                .verify(CONNECT_TIMEOUT)
                .getSession();
    }

    public static ClientSession createAuthenticatedClientSession(String username, SshClient client, int port)
            throws IOException {
        ClientSession session = createClientSession(username, client, port);
        try {
            ClientSession authSession = createAuthenticatedClientSession(session, username);
            session = null;     // avoid auto-close at finally clause
            return authSession;
        } finally {
            if (session != null) {
                session.close();
            }
        }
    }

    public static ClientSession createAuthenticatedClientSession(ClientSession session, String username) throws IOException {
        session.addPasswordIdentity(username);
        session.auth().verify(AUTH_TIMEOUT);
        return session;
    }

    public static IoServiceFactoryFactory getIoServiceProvider() {
        DefaultIoServiceFactoryFactory factory = DefaultIoServiceFactoryFactory.getDefaultIoServiceFactoryFactoryInstance();
        return factory.getIoServiceProvider();
    }

    public static void assumeNotIoServiceProvider(
            String message, Collection<BuiltinIoServiceFactoryFactories> excluded) {
        if (GenericUtils.isEmpty(excluded)) {
            return;
        }

        assumeNotIoServiceProvider(message, getIoServiceProvider(), excluded);
    }

    public static void assumeNotIoServiceProvider(
            String message, AbstractFactoryManager manager,
            Collection<BuiltinIoServiceFactoryFactories> excluded) {
        assumeNotIoServiceProvider(message, manager.getIoServiceFactoryFactory(), excluded);
    }

    public static void assumeNotIoServiceProvider(
            String message, IoServiceFactoryFactory provider,
            Collection<BuiltinIoServiceFactoryFactories> excluded) {
        if (GenericUtils.isEmpty(excluded)) {
            return;
        }

        Class<?> clazz = provider.getClass();
        String clazzName = clazz.getName();
        BuiltinIoServiceFactoryFactories match = excluded.stream()
                .filter(f -> clazzName.equals(f.getFactoryClassName()))
                .findFirst()
                .orElse(null);
        Assumptions.assumeTrue(match == null, message + " - skip factory=" + match);
    }
}
