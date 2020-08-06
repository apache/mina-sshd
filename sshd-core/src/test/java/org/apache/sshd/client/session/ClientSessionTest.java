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

package org.apache.sshd.client.session;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.rmi.ServerException;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.AttributeRepository.AttributeKey;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.BogusPasswordAuthenticator;
import org.apache.sshd.util.test.CommandExecutionHelper;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ClientSessionTest extends BaseTestSupport {

    private static SshServer sshd;
    private static SshClient client;
    private static int port;

    public ClientSessionTest() {
        super();
    }

    @BeforeClass
    public static void setupClientAndServer() throws Exception {
        sshd = CoreTestSupportUtils.setupTestServer(ClientSessionTest.class);
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestClient(ClientSessionTest.class);
        client.start();
    }

    @AfterClass
    public static void tearDownClientAndServer() throws Exception {
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

    @Before
    public void setUp() {
        sshd.setPasswordAuthenticator(BogusPasswordAuthenticator.INSTANCE);
        sshd.setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
        sshd.setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator.NONE);
    }

    @Test
    public void testDefaultExecuteCommandMethod() throws Exception {
        String expectedCommand = getCurrentTestName() + "-CMD";
        String expectedResponse = getCurrentTestName() + "-RSP";
        sshd.setCommandFactory((session, command) -> new CommandExecutionHelper(command) {
            private boolean cmdProcessed;

            @Override
            protected boolean handleCommandLine(String command) throws Exception {
                assertEquals("Mismatched incoming command", expectedCommand, command);
                assertFalse("Duplicated command call", cmdProcessed);
                OutputStream stdout = getOutputStream();
                stdout.write(expectedResponse.getBytes(StandardCharsets.US_ASCII));
                stdout.flush();
                cmdProcessed = true;
                return false;
            }
        });

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(CONNECT_TIMEOUT)
                .getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            // NOTE !!! The LF is only because we are using a buffered reader on the server end to read the command
            String actualResponse = session.executeRemoteCommand(expectedCommand + "\n");
            assertEquals("Mismatched command response", expectedResponse, actualResponse);
        }
    }

    @Test
    public void testExceptionThrownIfRemoteStderrWrittenTo() throws Exception {
        String expectedCommand = getCurrentTestName() + "-CMD";
        String expectedErrorMessage = getCurrentTestName() + "-ERR";
        sshd.setCommandFactory((session, command) -> new CommandExecutionHelper(command) {
            private boolean cmdProcessed;

            @Override
            protected boolean handleCommandLine(String command) throws Exception {
                assertEquals("Mismatched incoming command", expectedCommand, command);
                assertFalse("Duplicated command call", cmdProcessed);
                OutputStream stderr = getErrorStream();
                stderr.write(expectedErrorMessage.getBytes(StandardCharsets.US_ASCII));
                stderr.flush();
                cmdProcessed = true;
                return false;
            }
        });

        String actualErrorMessage = null;
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(CONNECT_TIMEOUT)
                .getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            // NOTE !!! The LF is only because we are using a buffered reader on the server end to read the command
            String response = session.executeRemoteCommand(expectedCommand + "\n");
            fail("Unexpected successful response: " + response);
        } catch (Exception e) {
            if (!(e instanceof RemoteException)) {
                throw e;
            }

            Throwable cause = e.getCause();
            if (!(cause instanceof ServerException)) {
                throw e;
            }

            actualErrorMessage = cause.getMessage();
        }

        assertEquals("Mismatched captured error message", expectedErrorMessage, actualErrorMessage);
    }

    @Test
    public void testExceptionThrownIfNonZeroExitStatus() throws Exception {
        String expectedCommand = getCurrentTestName() + "-CMD";
        int expectedErrorCode = 7365;
        sshd.setCommandFactory((session, command) -> new CommandExecutionHelper(command) {
            private boolean cmdProcessed;

            @Override
            protected void onExit(int exitValue, String exitMessage) {
                super.onExit((exitValue == 0) ? expectedErrorCode : exitValue, exitMessage);
            }

            @Override
            protected boolean handleCommandLine(String command) throws Exception {
                assertEquals("Mismatched incoming command", expectedCommand, command);
                assertFalse("Duplicated command call", cmdProcessed);
                OutputStream stdout = getOutputStream();
                stdout.write(command.getBytes(StandardCharsets.US_ASCII));
                stdout.flush();
                cmdProcessed = true;
                return false;
            }
        });

        String actualErrorMessage = null;
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(CONNECT_TIMEOUT)
                .getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            // NOTE !!! The LF is only because we are using a buffered reader on the server end to read the command
            String response = session.executeRemoteCommand(expectedCommand + "\n");
            fail("Unexpected successful response: " + response);
        } catch (Exception e) {
            if (!(e instanceof RemoteException)) {
                throw e;
            }

            Throwable cause = e.getCause();
            if (!(cause instanceof ServerException)) {
                throw e;
            }

            actualErrorMessage = cause.getMessage();
        }

        assertEquals("Mismatched captured error code", Integer.toString(expectedErrorCode), actualErrorMessage);
    }

    @Test // see SSHD-859
    public void testConnectionContextPropagation() throws Exception {
        AttributeRepository expected = AttributeRepository.ofKeyValuePair(
                new AttributeKey<String>(), getCurrentTestName());
        AtomicInteger creationCount = new AtomicInteger(0);
        SessionListener listener = new SessionListener() {
            @Override
            public void sessionCreated(Session session) {
                AttributeRepository actual = ((ClientSession) session).getConnectionContext();
                assertSame("Mismatched connection context", expected, actual);
                creationCount.incrementAndGet();
            }
        };

        try {
            client.addSessionListener(listener);

            try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port, expected)
                    .verify(CONNECT_TIMEOUT)
                    .getSession()) {
                session.addPasswordIdentity(getCurrentTestName());
                session.auth().verify(AUTH_TIMEOUT);
                assertEquals("Session listener invocation count mismatch", 1, creationCount.getAndSet(0));
            }
        } finally {
            client.removeSessionListener(listener);
        }
    }

    @Test // SSHD-1050
    public void testAuthGetsNotifiedIfErrorBeforeFirstAuth() throws Exception {
        testEarlyErrorAuthAttempts(1);
    }

    @Test // SSHD-1050
    public void testSecondAuthNotifiedAfterEarlyError() throws Exception {
        testEarlyErrorAuthAttempts(3);
    }

    private void testEarlyErrorAuthAttempts(int maxAttempts) throws Exception {
        int limit = CoreModuleProperties.MAX_IDENTIFICATION_SIZE.getRequired(sshd);
        String line = getClass().getCanonicalName() + "#" + getCurrentTestName();
        StringBuilder sb = new StringBuilder(limit + line.length());
        while (sb.length() <= limit) {
            if (sb.length() > 0) {
                sb.append(CoreModuleProperties.SERVER_EXTRA_IDENT_LINES_SEPARATOR);
            }
            sb.append(line);
        }
        CoreModuleProperties.SERVER_EXTRA_IDENTIFICATION_LINES.set(sshd, sb.toString());

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(CONNECT_TIMEOUT)
                .getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            // Give time to the client to signal the overflow in server identification
            Thread.sleep(AUTH_TIMEOUT.toMillis() / 2L);

            for (int index = 1; index <= maxAttempts; index++) {
                String authId = "Auth " + index + "/" + maxAttempts;
                outputDebugMessage("%s(%s)", getCurrentTestName(), authId);

                AuthFuture future = session.auth();
                assertTrue(authId + " not completed on time", future.await(AUTH_TIMEOUT));
                assertTrue(authId + " has no result", future.isDone());
                assertFalse(authId + " unexpected success", future.isSuccess());
                assertTrue(authId + " not marked as failed", future.isFailure());

                Throwable exception = future.getException();
                String message = exception.getMessage();
                assertTrue(authId + " invalid exception message: " + message, message.contains("too many header lines"));
            }
        } finally {
            CoreModuleProperties.SERVER_EXTRA_IDENTIFICATION_LINES.set(sshd, null);
        }
    }
}
