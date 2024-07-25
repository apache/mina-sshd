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
package org.apache.sshd.common.session;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.global.OpenSshHostKeysHandler;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.RequestHandler;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.future.GlobalRequestFuture;
import org.apache.sshd.common.global.GlobalRequestException;
import org.apache.sshd.common.session.helpers.AbstractConnectionServiceRequestHandler;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for sending global requests.
 */
public class GlobalRequestTest extends BaseTestSupport {
    private SshServer sshd;
    private SshClient client;
    private int port;

    public GlobalRequestTest() {
        super();
    }

    @BeforeEach
    void setUp() throws Exception {
        sshd = setupTestServer();
        sshd.start();
        port = sshd.getPort();

        client = setupTestClient();
    }

    @AfterEach
    void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
        if (client != null) {
            client.stop();
        }
    }

    @Test
    void singleRequestNoReply() throws Exception {
        AtomicBoolean wrongWantReply = new AtomicBoolean(false);
        CountDownLatch latch = new CountDownLatch(1);
        List<RequestHandler<ConnectionService>> globalHandlers = new ArrayList<>(sshd.getGlobalRequestHandlers());
        final String testRequest = getCurrentTestName() + "@sshd.org";
        globalHandlers.add(new AbstractConnectionServiceRequestHandler() {
            @Override
            public Result process(ConnectionService connectionService, String request, boolean wantReply, Buffer buffer)
                    throws Exception {
                if (testRequest.equals(request)) {
                    latch.countDown();
                    if (wantReply) {
                        wrongWantReply.set(true);
                        return Result.ReplyFailure;
                    }
                    return Result.Replied;
                }
                return Result.Unsupported;
            }
        });
        sshd.setGlobalRequestHandlers(globalHandlers);
        client.start();
        try (ClientSession session
                = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT).getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_GLOBAL_REQUEST);
            buffer.putString(testRequest);
            buffer.putBoolean(false); // want-reply false
            Buffer reply = session.request(testRequest, buffer, DEFAULT_TIMEOUT);
            assertNotNull(reply, "Expected a (fake) reply");
            assertEquals(0, reply.available(), "Expected a (fake) success");
            // Check that the server got it. Should take much less than 5 seconds.
            assertTrue(latch.await(5, TimeUnit.SECONDS), "Server did not get request");
        }
        assertFalse(wrongWantReply.get(), "Had a wrong want-reply");
    }

    @Test
    void overlappedRequests() throws Exception {
        final int numberOfRequests = 6;
        CountDownLatch latch = new CountDownLatch(numberOfRequests);
        List<RequestHandler<ConnectionService>> globalHandlers = new ArrayList<>(sshd.getGlobalRequestHandlers());
        final String testRequest = getCurrentTestName() + "@sshd.org";
        globalHandlers.add(new AbstractConnectionServiceRequestHandler() {

            private int count;

            private boolean extraRequests;

            @Override
            public Result process(ConnectionService connectionService, String request, boolean wantReply, Buffer buffer)
                    throws Exception {
                boolean sendReplies = false;
                if (testRequest.equals(request)) {
                    latch.countDown();
                    count++;
                    if (extraRequests) {
                        return Result.ReplySuccess;
                    }
                    sendReplies = true;
                } else if (request.endsWith("-unimplemented")) {
                    latch.countDown();
                    // Trigger unimplemented handler
                    connectionService.process(255, buffer);
                    sendReplies = true;
                }
                if (sendReplies) {
                    if (latch.getCount() == 0) {
                        extraRequests = true;
                        // Send alternating success or failure messages.
                        Session session = connectionService.getSession();
                        byte[] cmds = { SshConstants.SSH_MSG_REQUEST_SUCCESS, SshConstants.SSH_MSG_REQUEST_FAILURE };
                        for (int i = 0; i < count; i++) {
                            Buffer reply = session.createBuffer(cmds[i % 2], 2);
                            if (i % 2 == 0) {
                                reply.putByte((byte) ('1' + i));
                            }
                            session.writePacket(reply);
                        }
                    }
                    return Result.Replied;
                }
                return Result.Unsupported;
            }
        });
        sshd.setGlobalRequestHandlers(globalHandlers);
        client.start();
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT)
                .getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);

            GlobalRequestFuture[] requests = new GlobalRequestFuture[numberOfRequests];
            for (int i = 0; i < numberOfRequests; i++) {
                Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_GLOBAL_REQUEST);
                String req = testRequest + (((i % 3) == 2) ? "-unimplemented" : "");
                buffer.putString(req);
                buffer.putBoolean(true); // want-reply true
                requests[i] = session.request(buffer, req, null);
            }
            // Now wait for them one by one and check them
            for (int i = 0; i < numberOfRequests; i++) {
                GlobalRequestFuture request = requests[i];
                request.await(DEFAULT_TIMEOUT);
                assertTrue(request.isDone(), "Unexpected timeout after " + DEFAULT_TIMEOUT + "on request " + i);
            }
            // Check that the server got it. Should take much less than 5 seconds.
            assertTrue(latch.await(5, TimeUnit.SECONDS), "Server did not get all requests");
            int j = 0;
            for (int i = 0; i < numberOfRequests; i++) {
                GlobalRequestFuture request = requests[i];
                Throwable failure;
                switch (i % 3) {
                    case 0: {
                        j++;
                        Buffer reply = request.getBuffer();
                        assertNotNull(reply, "Expected success for request " + i);
                        assertEquals((byte) ('1' + j - 1), reply.getByte(), "Expected a success");
                        break;
                    }
                    case 1:
                        j++;
                        failure = request.getException();
                        assertNotNull(failure, "Expected failure for request " + i);
                        assertTrue(failure instanceof GlobalRequestException, "Unexpected failure type");
                        assertEquals(SshConstants.SSH_MSG_REQUEST_FAILURE,
                                ((GlobalRequestException) failure).getCode(),
                                "Unexpected failure reason for request " + i);
                        assertTrue(failure.getMessage().contains("SSH_MSG_REQUEST_FAILURE"),
                                "Unexpected failure message for request " + i);
                        break;
                    default:
                        failure = request.getException();
                        assertNotNull(failure, "Expected failure for request " + i);
                        assertTrue(failure instanceof GlobalRequestException, "Unexpected failure type");
                        assertEquals(SshConstants.SSH_MSG_UNIMPLEMENTED,
                                ((GlobalRequestException) failure).getCode(),
                                "Unexpected failure reason for request " + i);
                        assertTrue(failure.getMessage().contains("SSH_MSG_UNIMPLEMENTED"),
                                "Unexpected failure message for request " + i);
                        break;
                }
            }
            // Make another normal request just to be sure.
            Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_GLOBAL_REQUEST);
            buffer.putString(testRequest);
            buffer.putBoolean(true); // want-reply true
            Buffer reply = session.request(testRequest, buffer, DEFAULT_TIMEOUT);
            assertNotNull(reply, "Expected a success");
        }
    }

    @Test
    void globalRequestWithReplyInMessageHandling() throws Exception {
        // Use a crude implementation of the hostkey rotation OpenSSH extension. Note that the implementation in
        // Apache MINA sshd server is incomplete, and for RSA keys does not match the OpenSSH implementation.
        List<RequestHandler<ConnectionService>> globalHandlers = new ArrayList<>(sshd.getGlobalRequestHandlers());
        final String testRequest = getCurrentTestName() + "@sshd.org";
        // Apache MINA sshd doesn't implement the server-side sending of hostkeys-00@openssh.com yet (should occur
        // right after successful user authentication), and with only one host key, it shouldn't send that message
        // anyway even if it was implemented. So we fake this by telling the server explicitly that it should
        // send us such a message via an extra global request ('testRequest') from the client.
        globalHandlers.add(new AbstractConnectionServiceRequestHandler() {

            @Override
            public Result process(ConnectionService connectionService, String request, boolean wantReply, Buffer buffer)
                    throws Exception {
                if (testRequest.equals(request)) {
                    Session session = connectionService.getSession();
                    Buffer hostKeysBuffer = session.createBuffer(SshConstants.SSH_MSG_GLOBAL_REQUEST);
                    hostKeysBuffer.putString("hostkeys-00@openssh.com");
                    hostKeysBuffer.putBoolean(false); // want-reply
                    sshd.getKeyPairProvider().loadKeys(session).forEach(kp -> hostKeysBuffer.putPublicKey(kp.getPublic()));
                    session.writePacket(hostKeysBuffer);
                    return Result.Replied;
                }
                return Result.Unsupported;
            }
        });
        sshd.setGlobalRequestHandlers(globalHandlers);
        GlobalRequestFuture[] req = { null };
        List<PublicKey> keysFromServer = new ArrayList<>();
        CountDownLatch latch = new CountDownLatch(1);
        client.setGlobalRequestHandlers(Collections.singletonList(new OpenSshHostKeysHandler() {

            @Override
            protected Result handleHostKeys(
                    Session session, Collection<? extends PublicKey> keys, boolean wantReply,
                    Buffer buffer)
                    throws Exception {
                ValidateUtils.checkTrue(!wantReply, "Unexpected reply required for the host keys of %s", session);
                assertFalse(GenericUtils.isEmpty(keys));
                // Let the server prove ownership of all these keys
                Buffer requestBuffer = session.createBuffer(SshConstants.SSH_MSG_GLOBAL_REQUEST);
                requestBuffer.putString("hostkeys-prove-00@openssh.com");
                requestBuffer.putBoolean(true); // want-reply
                keys.forEach(requestBuffer::putPublicKey);
                keysFromServer.addAll(keys);
                // Make the request here synchronously, handle the reply asynchronously later on. In a real client-side
                // implementation, you'd have to use a Thread or an ExecutorService, but here in the test we can just
                // handle it in the test thread below.
                //
                // The split between making the request here and handling the reply asynchronously is a bit artificial
                // and serves only to illustrate that this is possible. However, one could also execute the whole
                // request asynchronously in a thread, with the request itself being a normal synchronous
                // session.request() invocation.
                req[0] = session.request(requestBuffer, "hostkeys-prove-00@openssh.com", null);
                latch.countDown();
                return Result.Replied;
            }
        }));
        client.start();
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT)
                .getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);
            // Tell the server to send us the hostkeys-00 message
            Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_GLOBAL_REQUEST);
            buffer.putString(testRequest);
            buffer.putBoolean(false); // want-reply
            // For once use session.request() instead of session.writePacket() to make the request.
            session.request(testRequest, buffer, DEFAULT_TIMEOUT);
            // Wait until we've received the hostkeys-00 message, and have made our hostkeys-prove-00 request.
            assertTrue(latch.await(5, TimeUnit.SECONDS), "Did not get hostkeys-00 message in time");
            assertNotNull(req[0], "Did not make hostkeys-prove-00 request");
            // Wait until we have the server's hostkeys-prove-00 reply.
            assertTrue(req[0].await(DEFAULT_TIMEOUT), "Did not get hostkeys-prove-00 reply in time");
            Buffer reply = req[0].getBuffer();
            assertNotNull(req[0], "Got a null hostkeys-prove-00 reply");
            // We should have as many signatures as we had gotten keys.
            Collection<NamedFactory<Signature>> factories = client.getSignatureFactories();
            keysFromServer.forEach(k -> {
                byte[] signature = reply.getBytes();
                // An Apache MINA sshd server uses the key type always, even for RSA keys (i.e., the SHA1 ssh-rsa
                // signature). An OpenSSH server uses the signature algorithm negotiated in KEX if that was an RSA key
                // and signature. (This protocol doesn't seem to be well designed. Would be better if the reply
                // contained the signature algorithm identifiers.)
                String algo = KeyUtils.getKeyType(k);
                // Verify the signature.
                Signature verifier = NamedFactory.create(factories, algo);
                Buffer expected = new ByteArrayBuffer();
                expected.putString("hostkeys-prove-00@openssh.com");
                expected.putBytes(session.getSessionId());
                expected.putPublicKey(k);
                try {
                    verifier.initVerifier(session, k);
                    verifier.update(session, expected.array(), expected.rpos(), expected.available());
                    assertTrue(verifier.verify(session, signature), "Signature does not match");
                } catch (Exception e) {
                    throw new RuntimeException("Signature verification failed", e);
                }
            });
            assertEquals(0, reply.available(), "Did not consume all bytes from the reply");
        }
    }

    @Test
    void globalRequestWithReplyHandler() throws Exception {
        // This is the same as above, but using a ReplyHandler. The whole key rotation exchange can be done completely
        // inside the OpenSshHostKeysHandler without any need for any extra threads. The framework's thread handling the
        // reply message will invoke the handler.
        List<RequestHandler<ConnectionService>> globalHandlers = new ArrayList<>(sshd.getGlobalRequestHandlers());
        final String testRequest = getCurrentTestName() + "@sshd.org";
        // Fake 'testRequest' handler.
        globalHandlers.add(new AbstractConnectionServiceRequestHandler() {

            @Override
            public Result process(ConnectionService connectionService, String request, boolean wantReply, Buffer buffer)
                    throws Exception {
                if (testRequest.equals(request)) {
                    Session session = connectionService.getSession();
                    Buffer hostKeysBuffer = session.createBuffer(SshConstants.SSH_MSG_GLOBAL_REQUEST);
                    hostKeysBuffer.putString("hostkeys-00@openssh.com");
                    hostKeysBuffer.putBoolean(false); // want-reply
                    sshd.getKeyPairProvider().loadKeys(session).forEach(kp -> hostKeysBuffer.putPublicKey(kp.getPublic()));
                    session.writePacket(hostKeysBuffer);
                    return Result.Replied;
                }
                return Result.Unsupported;
            }
        });
        sshd.setGlobalRequestHandlers(globalHandlers);
        CountDownLatch replyHandled = new CountDownLatch(1);
        List<String> testFailures = new ArrayList<>();
        client.setGlobalRequestHandlers(Collections.singletonList(new OpenSshHostKeysHandler() {

            @Override
            protected Result handleHostKeys(
                    Session session, Collection<? extends PublicKey> keys, boolean wantReply,
                    Buffer buffer)
                    throws Exception {
                ValidateUtils.checkTrue(!wantReply, "Unexpected reply required for the host keys of %s", session);
                assertFalse(GenericUtils.isEmpty(keys));
                // Let the server prove ownership of all these keys
                Buffer requestBuffer = session.createBuffer(SshConstants.SSH_MSG_GLOBAL_REQUEST);
                requestBuffer.putString("hostkeys-prove-00@openssh.com");
                requestBuffer.putBoolean(true); // want-reply
                keys.forEach(requestBuffer::putPublicKey);
                session.request(requestBuffer, "hostkeys-prove-00@openssh.com", (cmd, reply) -> {
                    keys.forEach(k -> {
                        byte[] signature = reply.getBytes();
                        String algo = KeyUtils.getKeyType(k);
                        // Verify the signature.
                        Signature verifier = NamedFactory.create(client.getSignatureFactories(), algo);
                        Buffer expected = new ByteArrayBuffer();
                        expected.putString("hostkeys-prove-00@openssh.com");
                        expected.putBytes(session.getSessionId());
                        expected.putPublicKey(k);
                        try {
                            verifier.initVerifier(session, k);
                            verifier.update(session, expected.array(), expected.rpos(), expected.available());
                            // Cannot assert here; it's in another thread
                            if (!verifier.verify(session, signature)) {
                                testFailures.add("Signature did not validate for " + KeyUtils.getKeyType(k) + " "
                                                 + KeyUtils.getFingerPrint(k));
                            }
                        } catch (Exception e) {
                            testFailures.add("Signature verification failed " + e);
                            throw new RuntimeException("Signature verification failed", e);
                        }
                        if (reply.available() > 0) {
                            testFailures.add("Did not consume all bytes from the reply");
                        }
                    });
                    replyHandled.countDown();
                });
                return Result.Replied;
            }
        }));
        client.start();
        try (ClientSession session = client.connect(getCurrentTestName(), TEST_LOCALHOST, port).verify(CONNECT_TIMEOUT)
                .getSession()) {
            session.addPasswordIdentity(getCurrentTestName());
            session.auth().verify(AUTH_TIMEOUT);
            // Tell the server to send us the hostkeys-00 message
            Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_GLOBAL_REQUEST);
            buffer.putString(testRequest);
            buffer.putBoolean(false); // want-reply
            session.request(testRequest, buffer, DEFAULT_TIMEOUT);
            // Wait until all keys verified.
            assertTrue(replyHandled.await(10, TimeUnit.SECONDS), "Did not handle hostkeys-prove-00 message in time");
            assertEquals("", String.join(System.lineSeparator(), testFailures), "Test failures");
        }
    }
}
