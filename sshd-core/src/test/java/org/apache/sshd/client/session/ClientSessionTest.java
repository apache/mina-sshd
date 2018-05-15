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
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.command.CommandFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommandExecutionHelper;
import org.apache.sshd.util.test.Utils;
import org.junit.AfterClass;
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
        sshd = Utils.setupTestServer(ClientSessionTest.class);
        sshd.start();
        port = sshd.getPort();

        client = Utils.setupTestClient(ClientSessionTest.class);
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

    @Test
    public void testDefaultExecuteCommandMethod() throws Exception {
        final String expectedCommand = getCurrentTestName() + "-CMD";
        final String expectedResponse = getCurrentTestName() + "-RSP";
        sshd.setCommandFactory(new CommandFactory() {
            @Override
            public String getName() {
                return getCurrentTestName();
            }

            @Override
            public Command createCommand(String command) {
                return new CommandExecutionHelper(command) {
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
                };
            }
        });

        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);

            // NOTE !!! The LF is only because we are using a buffered reader on the server end to read the command
            String actualResponse = session.executeRemoteCommand(expectedCommand + "\n");
            assertEquals("Mismatched command response", expectedResponse, actualResponse);
        }
    }

    @Test
    public void testExceptionThrownIfRemoteStderrWrittenTo() throws Exception {
        final String expectedCommand = getCurrentTestName() + "-CMD";
        final String expectedErrorMessage = getCurrentTestName() + "-ERR";
        sshd.setCommandFactory(new CommandFactory() {
            @Override
            public String getName() {
                return getCurrentTestName();
            }

            @Override
            public Command createCommand(String command) {
                return new CommandExecutionHelper(command) {
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
                };
            }
        });

        String actualErrorMessage = null;
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);

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
        final String expectedCommand = getCurrentTestName() + "-CMD";
        final int exepectedErrorCode = 7365;
        sshd.setCommandFactory(new CommandFactory() {
            @Override
            public String getName() {
                return getCurrentTestName();
            }

            @Override
            public Command createCommand(String command) {
                return new CommandExecutionHelper(command) {
                    private boolean cmdProcessed;

                    @Override
                    public void onExit(int exitValue, String exitMessage) {
                        super.onExit((exitValue == 0) ? exepectedErrorCode : exitValue, exitMessage);
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
                };
            }
        });

        String actualErrorMessage = null;
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(7L, TimeUnit.SECONDS).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(5L, TimeUnit.SECONDS);

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

        assertEquals("Mismatched captured error code", Integer.toString(exepectedErrorCode), actualErrorMessage);
    }
}
