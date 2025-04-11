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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.rmi.ServerException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.AttributeRepository.AttributeKey;
import org.apache.sshd.common.channel.ChannelPipedInputStream;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.BogusPasswordAuthenticator;
import org.apache.sshd.util.test.CommandExecutionHelper;
import org.apache.sshd.util.test.CoreTestSupportUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
public class ClientSessionTest extends BaseTestSupport {

    private static SshServer sshd;
    private static SshClient client;
    private static int port;

    public ClientSessionTest() {
        super();
    }

    @BeforeAll
    static void setupClientAndServer() throws Exception {
        sshd = CoreTestSupportUtils.setupTestServer(ClientSessionTest.class);
        sshd.start();
        port = sshd.getPort();

        client = CoreTestSupportUtils.setupTestClient(ClientSessionTest.class);
        client.start();
    }

    @AfterAll
    static void tearDownClientAndServer() throws Exception {
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

    @BeforeEach
    void setUp() {
        sshd.setPasswordAuthenticator(BogusPasswordAuthenticator.INSTANCE);
        sshd.setPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
        sshd.setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator.NONE);
    }

    @Test
    void defaultExecuteCommandMethod() throws Exception {
        String expectedCommand = getCurrentTestName() + "-CMD";
        String expectedResponse = getCurrentTestName() + "-RSP";
        sshd.setCommandFactory((session, command) -> new CommandExecutionHelper(command) {
            private boolean cmdProcessed;

            @Override
            protected boolean handleCommandLine(String command) throws Exception {
                assertEquals(expectedCommand, command, "Mismatched incoming command");
                assertFalse(cmdProcessed, "Duplicated command call");
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
            assertEquals(expectedResponse, actualResponse, "Mismatched command response");
        }
    }

    @Test
    void exceptionThrownIfRemoteStderrWrittenTo() throws Exception {
        String expectedCommand = getCurrentTestName() + "-CMD";
        String expectedErrorMessage = getCurrentTestName() + "-ERR";
        sshd.setCommandFactory((session, command) -> new CommandExecutionHelper(command) {
            private boolean cmdProcessed;

            @Override
            protected boolean handleCommandLine(String command) throws Exception {
                assertEquals(expectedCommand, command, "Mismatched incoming command");
                assertFalse(cmdProcessed, "Duplicated command call");
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

        assertEquals(expectedErrorMessage, actualErrorMessage, "Mismatched captured error message");
    }

    @Test
    void exceptionThrownIfNonZeroExitStatus() throws Exception {
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
                assertEquals(expectedCommand, command, "Mismatched incoming command");
                assertFalse(cmdProcessed, "Duplicated command call");
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

        assertEquals(Integer.toString(expectedErrorCode), actualErrorMessage, "Mismatched captured error code");
    }

    @Test
    void executeCommandMethodWithConfigurableTimeout() throws Exception {
        String expectedCommand = getCurrentTestName() + "-CMD";
        String expectedResponse = getCurrentTestName() + "-RSP";
        Duration timeout = Duration.ofMillis(10000L);
        sshd.setCommandFactory((session, command) -> new CommandExecutionHelper(command) {
            private boolean cmdProcessed;

            @Override
            protected boolean handleCommandLine(String command) throws Exception {
                assertEquals(expectedCommand, command, "Mismatched incoming command");
                assertFalse(cmdProcessed, "Duplicated command call");
                OutputStream stdout = getOutputStream();
                Thread.sleep(500L);
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
            String actualResponse = session.executeRemoteCommand(expectedCommand + "\n", timeout);
            assertEquals(expectedResponse, actualResponse, "Mismatched command response");
        }
    }

    @Test
    void exceptionThrownOnExecuteCommandTimeout() throws Exception {
        String expectedCommand = getCurrentTestName() + "-CMD";
        Duration timeout = Duration.ofMillis(500L);

        sshd.setCommandFactory((session, command) -> new CommandExecutionHelper(command) {
            private boolean cmdProcessed;

            @Override
            protected boolean handleCommandLine(String command) throws Exception {
                assertEquals(expectedCommand, command, "Mismatched incoming command");
                assertFalse(cmdProcessed, "Duplicated command call");
                Thread.sleep(timeout.plusMillis(200L).toMillis());
                OutputStream stdout = getOutputStream();
                stdout.write(command.getBytes(StandardCharsets.US_ASCII));
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

            assertThrows(SocketTimeoutException.class, () -> {
                session.executeRemoteCommand(expectedCommand + "\n", timeout);
            });
        }
    }

    // see SSHD-859
    @Test
    void connectionContextPropagation() throws Exception {
        AttributeRepository expected = AttributeRepository.ofKeyValuePair(
                new AttributeKey<String>(), getCurrentTestName());
        AtomicInteger creationCount = new AtomicInteger(0);
        SessionListener listener = new SessionListener() {
            @Override
            public void sessionCreated(Session session) {
                AttributeRepository actual = ((ClientSession) session).getConnectionContext();
                assertSame(expected, actual, "Mismatched connection context");
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
                assertEquals(1, creationCount.getAndSet(0), "Session listener invocation count mismatch");
            }
        } finally {
            client.removeSessionListener(listener);
        }
    }

    // SSHD-1050
    @Test
    void authGetsNotifiedIfErrorBeforeFirstAuth() throws Exception {
        testEarlyErrorAuthAttempts(1);
    }

    // SSHD-1050
    @Test
    void secondAuthNotifiedAfterEarlyError() throws Exception {
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
                assertTrue(future.await(AUTH_TIMEOUT), authId + " not completed on time");
                assertTrue(future.isDone(), authId + " has no result");
                assertFalse(future.isSuccess(), authId + " unexpected success");
                assertTrue(future.isFailure(), authId + " not marked as failed");

                Throwable exception = future.getException();
                String message = exception.getMessage();
                assertTrue(message.contains("too many header lines"), authId + " invalid exception message: " + message);
            }
        } finally {
            CoreModuleProperties.SERVER_EXTRA_IDENTIFICATION_LINES.set(sshd, null);
        }
    }

    // SSHD-1276
    @Test
    void redirectCommandErrorStream() throws Exception {
        String expectedCommand = getCurrentTestName() + "-CMD";
        String expectedStdout = getCurrentTestName() + "-STDOUT";
        String expectedStderr = getCurrentTestName() + "-STDERR";
        sshd.setCommandFactory((session, command) -> new CommandExecutionHelper(command) {
            private boolean cmdProcessed;

            @Override
            protected boolean handleCommandLine(String command) throws Exception {
                assertEquals(expectedCommand, command, "Mismatched incoming command");
                assertFalse(cmdProcessed, "Duplicated command call");
                writeResponse(getOutputStream(), expectedStdout);
                writeResponse(getErrorStream(), expectedStderr);
                cmdProcessed = true;
                return false;
            }

            private void writeResponse(OutputStream out, String rsp) throws IOException {
                out.write(rsp.getBytes(StandardCharsets.US_ASCII));
                out.write((byte) '\n');
                out.flush();
            }
        });

        String response;
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port)
                .verify(CONNECT_TIMEOUT)
                .getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                // NOTE !!! The LF is only because we are using a buffered reader on the server end to read the command
                try (ClientChannel channel = session.createExecChannel(expectedCommand + "\n")) {
                    channel.setOut(baos);
                    channel.setRedirectErrorStream(true);

                    channel.open().verify(OPEN_TIMEOUT);
                    // Wait (forever) for the channel to close - signalling command finished
                    channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), CLOSE_TIMEOUT);
                }

                byte[] bytes = baos.toByteArray();
                response = new String(bytes, StandardCharsets.US_ASCII);
            }
        }

        String[] lines = GenericUtils.split(response, '\n');
        assertEquals(2, lines.length, "Mismatched response lines count");

        Collection<String> values = new ArrayList<>(Arrays.asList(lines));
        // We don't rely on the order the strings were written
        for (String expected : new String[] { expectedStdout, expectedStderr }) {
            if (!values.remove(expected)) {
                fail(expected + " not in response=" + values);
            }
        }

        assertTrue(values.isEmpty(), "Unexpected response remainders: " + values);
    }

    // SSHD-1303
    @Test
    void redirectCommandErrorStreamIsEmpty() throws Exception {
        String expectedCommand = getCurrentTestName() + "-CMD";
        String expectedStdout = getCurrentTestName() + "-STDOUT";
        String expectedStderr = getCurrentTestName() + "-STDERR";
        sshd.setCommandFactory((session, command) -> new CommandExecutionHelper(command) {
            private boolean cmdProcessed;

            @Override
            protected boolean handleCommandLine(String command) throws Exception {
                assertEquals(expectedCommand, command, "Mismatched incoming command");
                assertFalse(cmdProcessed, "Duplicated command call");
                writeResponse(getOutputStream(), expectedStdout);
                writeResponse(getErrorStream(), expectedStderr);
                cmdProcessed = true;
                return false;
            }

            private void writeResponse(OutputStream out, String rsp) throws IOException {
                out.write(rsp.getBytes(StandardCharsets.US_ASCII));
                out.write((byte) '\n');
                out.flush();
            }
        });

        String response;
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT)
                .getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                // NOTE !!! The LF is only because we are using a buffered reader on the server end to read the command
                try (ClientChannel channel = session.createExecChannel(expectedCommand + '\n')) {
                    channel.setRedirectErrorStream(true);

                    channel.open().verify(OPEN_TIMEOUT);
                    try (InputStream stderr = channel.getInvertedErr()) {
                        assertEquals(-1, stderr.read());
                    }
                    try (InputStream stdout = channel.getInvertedOut()) {
                        IoUtils.copy(stdout, baos, 32); // Use a small buffer on purpose
                    }
                }
                byte[] bytes = baos.toByteArray();
                response = new String(bytes, StandardCharsets.US_ASCII);
            }
        }

        String[] lines = GenericUtils.split(response, '\n');
        assertEquals(2, lines.length, "Mismatched response lines count");

        Collection<String> values = new ArrayList<>(Arrays.asList(lines));
        // We don't rely on the order the strings were written
        for (String expected : new String[] { expectedStdout, expectedStderr }) {
            if (!values.remove(expected)) {
                fail(expected + " not in response=" + values);
            }
        }

        assertTrue(values.isEmpty(), "Unexpected response remainders: " + values);
    }

    // SSHD-1302
    @Test
    void readInputStreamTwice() throws Exception {
        String expectedCommand = getCurrentTestName() + "-CMD";
        String expectedStdout = getCurrentTestName() + "-STDOUT";
        String expectedStderr = getCurrentTestName() + "-STDERR";
        sshd.setCommandFactory((session, command) -> new CommandExecutionHelper(command) {
            private boolean cmdProcessed;

            @Override
            protected boolean handleCommandLine(String command) throws Exception {
                assertEquals(expectedCommand, command, "Mismatched incoming command");
                assertFalse(cmdProcessed, "Duplicated command call");
                writeResponse(getOutputStream(), expectedStdout);
                writeResponse(getErrorStream(), expectedStderr);
                cmdProcessed = true;
                return false;
            }

            private void writeResponse(OutputStream out, String rsp) throws IOException {
                out.write(rsp.getBytes(StandardCharsets.US_ASCII));
                out.write((byte) '\n');
                out.flush();
            }
        });

        String response;
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT)
                .getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                // NOTE !!! The LF is only because we are using a buffered reader on the server end to read the command
                try (ClientChannel channel = session.createExecChannel(expectedCommand + '\n')) {
                    channel.setRedirectErrorStream(true);

                    channel.open().verify(OPEN_TIMEOUT);

                    Thread.sleep(5000);
                    InputStream stdout = null;
                    try {
                        stdout = channel.getInvertedOut();
                        assertTrue(stdout instanceof ChannelPipedInputStream);
                        assertTrue(((ChannelPipedInputStream) stdout).isOpen());
                        IoUtils.copy(stdout, baos, 32); // Use a small buffer on purpose
                        // The stream isn't closed yet. Reading now again should just return -1.
                        assertEquals(-1, stdout.read());
                        InputStream out = channel.getInvertedOut();
                        assertSame(out, stdout);
                        assertEquals(-1, out.read());
                        assertTrue(((ChannelPipedInputStream) stdout).isOpen());
                    } finally {
                        if (stdout != null) {
                            stdout.close();
                        }
                    }
                }
                byte[] bytes = baos.toByteArray();
                response = new String(bytes, StandardCharsets.US_ASCII);
            }
        }

        String[] lines = GenericUtils.split(response, '\n');
        assertEquals(2, lines.length, "Mismatched response lines count");

        Collection<String> values = new ArrayList<>(Arrays.asList(lines));
        // We don't rely on the order the strings were written
        for (String expected : new String[] { expectedStdout, expectedStderr }) {
            if (!values.remove(expected)) {
                fail(expected + " not in response=" + values);
            }
        }

        assertTrue(values.isEmpty(), "Unexpected response remainders: " + values);
    }
}
