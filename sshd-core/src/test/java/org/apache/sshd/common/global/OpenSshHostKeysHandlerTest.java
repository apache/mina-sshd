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
package org.apache.sshd.common.global;

import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Collection;

import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@Tag("NoIoTestCase")
@ExtendWith(MockitoExtension.class)
public class OpenSshHostKeysHandlerTest extends BaseTestSupport {

    @Mock
    private ConnectionService connectionService;

    private PublicKey key;
    private Buffer buffer;

    public OpenSshHostKeysHandlerTest() {
        super();
    }

    @BeforeEach
    void prepareBuffer() throws Exception {
        // Create an RSA key
        key = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
        // Serialize it twice to a buffer, but insert a fake item in between
        buffer = new ByteArrayBuffer();
        buffer.putPublicKey(key);
        buffer.putUInt(34);
        buffer.putString("unknown"); // Fake key type; 7 + 4 bytes length
        buffer.putString("followed by garbage"); // 19 + 4
        buffer.putPublicKey(key);
    }

    @Test
    void clientIgnoresUnknownKeys() throws Exception {
        boolean[] handlerCalled = { false };
        org.apache.sshd.client.global.OpenSshHostKeysHandler handler
                = new org.apache.sshd.client.global.OpenSshHostKeysHandler() {
                    @Override
                    protected Result handleHostKeys(
                            Session session, Collection<? extends PublicKey> keys, boolean wantReply,
                            Buffer buffer) throws Exception {
                        handlerCalled[0] = true;
                        assertEquals(2, keys.size(), "Unexpected number of keys");
                        for (PublicKey k : keys) {
                            assertTrue(KeyUtils.compareKeys(key, k), "Unexpected public key");
                        }
                        return Result.Replied;
                    }
                };
        handler.process(connectionService, org.apache.sshd.client.global.OpenSshHostKeysHandler.REQUEST, false, buffer);
        assertTrue(handlerCalled[0], "Handler should have been called");
    }

    @Test
    void serverThrowsOnUnknownKeys() throws Exception {
        boolean[] handlerCalled = { false };
        org.apache.sshd.server.global.OpenSshHostKeysHandler handler
                = new org.apache.sshd.server.global.OpenSshHostKeysHandler() {
                    @Override
                    protected Result handleHostKeys(
                            Session session, Collection<? extends PublicKey> keys, boolean wantReply,
                            Buffer buffer) throws Exception {
                        handlerCalled[0] = true;
                        return Result.Replied;
                    }
                };
        SshException e = assertThrows(SshException.class, () -> handler.process(connectionService,
                org.apache.sshd.server.global.OpenSshHostKeysHandler.REQUEST, false, buffer));
        assertFalse(handlerCalled[0], "Handler should not have been called");
        assertInstanceOf(GeneralSecurityException.class, e.getCause(), "Expected exception cause");
    }
}
