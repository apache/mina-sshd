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

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.session.ServerUserAuthService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyByte;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for password or keyboard-interactive asynchronous authentication.
 */
public class ServerUserAuthServiceAsyncTest {

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void replacedMethodDiscardsOldResult(boolean result) throws Exception {
        AsyncAuthException old = new AsyncAuthException();
        StepAuth password = new StepAuth("password", pending(old));
        StepAuth publicKey = new StepAuth("publickey", () -> null);
        Fixture f = new Fixture(factory(password), factory(publicKey));
        f.request("password");
        f.request("publickey");
        old.setAuthed(result);
        f.assertUnchanged(publicKey, 0);
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void replacedInstanceKeepsNewPendingResult(boolean result) throws Exception {
        AsyncAuthException old = new AsyncAuthException();
        AsyncAuthException current = new AsyncAuthException();
        StepAuth first = new StepAuth("password", pending(old));
        StepAuth second = new StepAuth("password", pending(current));
        Fixture f = new Fixture(factory(first, second));
        f.request("password");
        f.request("password");
        old.setAuthed(result);
        f.assertUnchanged(second, 0);
        current.setAuthed(true);
        f.assertSuccess();
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void sameAuthenticatorContinuationKeepsNewPendingResult(boolean result) throws Exception {
        AsyncAuthException old = new AsyncAuthException();
        AsyncAuthException current = new AsyncAuthException();
        StepAuth interactive = new StepAuth("keyboard-interactive", () -> null, pending(old), pending(current));
        Fixture f = new Fixture(factory(interactive));
        f.request("keyboard-interactive");
        f.continuation();
        f.continuation();
        old.setAuthed(result);
        f.assertUnchanged(interactive, 0);
        current.setAuthed(true);
        f.assertSuccess();
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void incompleteContinuationDiscardsOldResult(boolean result) throws Exception {
        AsyncAuthException old = new AsyncAuthException();
        StepAuth interactive = new StepAuth("keyboard-interactive", () -> null, pending(old), () -> null);
        Fixture f = new Fixture(factory(interactive));
        f.request("keyboard-interactive");
        f.continuation();
        f.continuation();
        old.setAuthed(result);
        f.assertUnchanged(interactive, 0);
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void destructionCannotCompleteSupersededRequest(boolean result) throws Exception {
        AsyncAuthException old = new AsyncAuthException();
        StepAuth password = new StepAuth("password", pending(old));
        password.onDestroy = () -> old.setAuthed(result);
        StepAuth publicKey = new StepAuth("publickey", () -> null);
        Fixture f = new Fixture(factory(password), factory(publicKey));
        f.request("password");
        f.request("publickey");
        f.assertUnchanged(publicKey, 0);
        assertEquals(1, password.destroyed);
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void alreadyCompletedResultIsDelivered(boolean result) throws Exception {
        AsyncAuthException completed = new AsyncAuthException();
        completed.setAuthed(result);
        StepAuth password = new StepAuth("password", pending(completed));
        Fixture f = new Fixture(factory(password));
        f.request("password");
        assertEquals(1, f.service.completions);
        assertEquals(1, password.destroyed);
        if (result) {
            f.assertSuccess();
        } else {
            verify(f.session, never()).signalAuthenticationSuccess(anyString(), anyString(), any());
            assertEquals(1, f.packets.size());
            assertEquals(SshConstants.SSH_MSG_USERAUTH_FAILURE, f.packets.get(0).getByte());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void serviceClosureDiscardsResult(boolean result) throws Exception {
        AsyncAuthException pending = new AsyncAuthException();
        StepAuth password = new StepAuth("password", pending(pending));
        Fixture f = new Fixture(factory(password));
        f.request("password");
        f.service.close(true);
        pending.setAuthed(result);
        f.assertUnchanged(password, 0);
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void sessionClosureDiscardsResult(boolean result) throws Exception {
        AsyncAuthException pending = new AsyncAuthException();
        StepAuth password = new StepAuth("password", pending(pending));
        Fixture f = new Fixture(factory(password));
        f.request("password");
        when(f.session.isClosing()).thenReturn(true);
        pending.setAuthed(result);
        f.assertUnchanged(password, 0);
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void authenticatedSessionDiscardsResult(boolean result) throws Exception {
        AsyncAuthException pending = new AsyncAuthException();
        StepAuth password = new StepAuth("password", pending(pending));
        Fixture f = new Fixture(factory(password));
        f.request("password");
        when(f.session.isAuthenticated()).thenReturn(true);
        pending.setAuthed(result);
        f.assertUnchanged(password, 0);
    }

    @Test
    void unsupportedRequestInvalidatesPendingResult() throws Exception {
        AsyncAuthException old = new AsyncAuthException();
        StepAuth password = new StepAuth("password", pending(old));
        Fixture f = new Fixture(factory(password));
        f.request("password");
        f.request("unsupported");
        old.setAuthed(true);
        assertEquals(1, f.packets.size());
        assertEquals(0, f.service.completions);
        verify(f.session, never()).signalAuthenticationSuccess(anyString(), anyString(), any());
    }

    @Test
    void malformedRequestInvalidatesPendingResult() throws Exception {
        AsyncAuthException old = new AsyncAuthException();
        StepAuth password = new StepAuth("password", pending(old));
        Fixture f = new Fixture(factory(password));
        f.request("password");
        assertThrows(RuntimeException.class,
                () -> f.service.process(SshConstants.SSH_MSG_USERAUTH_REQUEST, new ByteArrayBuffer()));
        old.setAuthed(true);
        assertEquals(0, f.service.completions);
        verify(f.session, never()).signalAuthenticationSuccess(anyString(), anyString(), any());
    }

    @Test
    void legitimateMethodSwitchCanComplete() throws Exception {
        AsyncAuthException old = new AsyncAuthException();
        StepAuth password = new StepAuth("password", pending(old));
        StepAuth publicKey = new StepAuth("publickey", () -> true);
        Fixture f = new Fixture(factory(password), factory(publicKey));
        f.request("password");
        f.request("publickey");
        old.setAuthed(false);
        verify(f.session).signalAuthenticationSuccess(anyString(), anyString(), any());
        assertEquals(0, f.service.completions);
        assertEquals(0, f.packets.size());
        assertEquals(1, publicKey.destroyed);
    }

    private static AuthStep pending(AsyncAuthException exception) {
        return () -> {
            throw exception;
        };
    }

    private static UserAuthFactory factory(StepAuth... authenticators) {
        Deque<StepAuth> remaining = new ArrayDeque<>(Arrays.asList(authenticators));
        return new UserAuthFactory() {
            @Override
            public String getName() {
                return authenticators[0].getName();
            }

            @Override
            public UserAuth createUserAuth(ServerSession session) {
                return remaining.removeFirst();
            }
        };
    }

    @FunctionalInterface
    private interface AuthStep {
        Boolean authenticate();
    }

    private static class StepAuth extends AbstractUserAuth {
        private final Deque<AuthStep> steps;
        private int destroyed;
        private Runnable onDestroy = () -> {
        };

        StepAuth(String method, AuthStep... steps) {
            super(method);
            this.steps = new ArrayDeque<>(Arrays.asList(steps));
        }

        @Override
        protected Boolean doAuth(Buffer buffer, boolean init) {
            return steps.removeFirst().authenticate();
        }

        @Override
        public void destroy() {
            destroyed++;
            onDestroy.run();
        }
    }

    private static class TrackingService extends ServerUserAuthService {
        private int completions;

        TrackingService(ServerSession session) throws IOException {
            super(session);
        }

        @Override
        protected synchronized void asyncAuth(int cmd, Buffer buffer, boolean authed) {
            completions++;
            super.asyncAuth(cmd, buffer, authed);
        }
    }

    private static class Fixture {
        private final ServerSession session = mock(ServerSession.class);
        private final List<Buffer> packets = new ArrayList<>();
        private final TrackingService service;

        Fixture(UserAuthFactory... factories) throws Exception {
            when(session.getProperties()).thenReturn(new HashMap<>());
            when(session.getUserAuthFactories()).thenReturn(Arrays.asList(factories));
            when(session.createBuffer(anyByte(), anyInt())).thenAnswer(invocation -> {
                Buffer buffer = new ByteArrayBuffer();
                buffer.putByte(invocation.getArgument(0));
                return buffer;
            });
            when(session.writePacket(any(Buffer.class))).thenAnswer(invocation -> {
                packets.add(invocation.getArgument(0));
                return null;
            });
            service = new TrackingService(session);
        }

        void request(String method) throws Exception {
            Buffer buffer = new ByteArrayBuffer();
            buffer.putString("alice");
            buffer.putString("ssh-connection");
            buffer.putString(method);
            service.process(SshConstants.SSH_MSG_USERAUTH_REQUEST, buffer);
        }

        void continuation() throws Exception {
            Buffer buffer = new ByteArrayBuffer();
            buffer.putByte(SshConstants.SSH_MSG_USERAUTH_INFO_RESPONSE);
            buffer.rpos(1);
            service.process(SshConstants.SSH_MSG_USERAUTH_INFO_RESPONSE, buffer);
        }

        void assertUnchanged(StepAuth current, int expectedPackets) throws Exception {
            assertEquals(0, service.completions);
            assertEquals(0, current.destroyed);
            assertEquals(expectedPackets, packets.size());
            verify(session, never()).signalAuthenticationSuccess(anyString(), anyString(), any());
        }

        void assertSuccess() throws Exception {
            assertEquals(1, service.completions);
            verify(session).signalAuthenticationSuccess(anyString(), anyString(), any());
            assertEquals(0, packets.size());
        }
    }
}
