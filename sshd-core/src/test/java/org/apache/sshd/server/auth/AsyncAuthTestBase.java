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

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import com.jcraft.jsch.JSchException;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.apache.sshd.util.test.EchoShellFactory;
import org.junit.After;
import org.junit.Test;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AsyncAuthTestBase extends BaseTestSupport {
    protected SshServer server;
    protected int port;

    private PasswordAuthenticator authenticator;

    protected AsyncAuthTestBase() {
        super();
    }

    public void startServer() throws Exception {
        startServer(null);
    }

    public void startServer(Duration timeout) throws Exception {
        if (server != null) {
            fail("Server already started");
        }
        server = CoreTestSupportUtils.setupTestFullSupportServer(SshServer.setUpDefaultServer());
        if (timeout != null) {
            CoreModuleProperties.AUTH_TIMEOUT.set(server, timeout);
        }

        Path tmpDir = Files.createDirectories(getTempTargetFolder());
        Path keyFile = tmpDir.resolve("hostkey.ser");
        server.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(keyFile));
        server.setPasswordAuthenticator(
                (username, password, session) -> authenticator.authenticate(username, password, session));
        server.setShellFactory(new EchoShellFactory());
        server.start();
        port = server.getPort();
    }

    @After
    public void stopServer() throws Exception {
        if (server != null) {
            server.stop();
        }
        server = null;
    }

    @Test
    public void testSyncAuthFailed() throws Exception {
        startServer();
        authenticator = (username, x, sess) -> false;
        assertFalse(authenticate());
    }

    @Test
    public void testSyncAuthSucceeded() throws Exception {
        startServer();
        authenticator = (username, x, sess) -> true;
        assertTrue(authenticate());
    }

    @Test
    public void testAsyncAuthFailed() throws Exception {
        startServer();
        authenticator = (username, x, sess) -> async(200, false);
        assertFalse(authenticate());
    }

    @Test
    public void testAsyncAuthSucceeded() throws Exception {
        startServer();
        authenticator = (username, x, sess) -> async(200, true);
        assertTrue(authenticate());
    }

    @Test
    public void testAsyncAuthTimeout() throws Exception {
        startServer(Duration.ofMillis(500));
        authenticator = (username, x, sess) -> asyncTimeout();
        try {
            authenticate();
        } catch (JSchException e) {
            assertTrue("Unexpected failure " + e.getMessage(), e.getMessage().startsWith("SSH_MSG_DISCONNECT"));
        }
    }

    @Test
    public void testAsyncAuthSucceededAfterTimeout() throws Exception {
        startServer(Duration.ofMillis(500));
        authenticator = (username, x, sess) -> async(1000, true);
        try {
            authenticate();
        } catch (JSchException e) {
            assertTrue("Unexpected failure " + e.getMessage(), e.getMessage().startsWith("SSH_MSG_DISCONNECT"));
        }
    }

    private boolean asyncTimeout() {
        throw new AsyncAuthException();
    }

    private boolean async(int delay, boolean result) {
        AsyncAuthException auth = new AsyncAuthException();
        new Thread(() -> doAsync(delay, result, auth)).start();
        throw auth;
    }

    private void doAsync(int delay, boolean result, AsyncAuthException auth) {
        try {
            Thread.sleep(delay);
        } catch (InterruptedException ignore) {
            // ignore
        } finally {
            auth.setAuthed(result);
        }
    }

    protected abstract boolean authenticate() throws Exception;

}
