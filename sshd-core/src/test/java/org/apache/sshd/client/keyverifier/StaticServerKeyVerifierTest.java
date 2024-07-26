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

package org.apache.sshd.client.keyverifier;

import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Random;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class StaticServerKeyVerifierTest extends BaseTestSupport {
    public StaticServerKeyVerifierTest() {
        super();
    }

    @Test
    void acceptAllServerKeyVerifier() throws Exception {
        testStaticServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE);
    }

    @Test
    void rejectAllServerKeyVerifier() throws Exception {
        testStaticServerKeyVerifier(RejectAllServerKeyVerifier.INSTANCE);
    }

    private void testStaticServerKeyVerifier(StaticServerKeyVerifier authenticator) throws Exception {
        Method method = ServerKeyVerifier.class.getMethod("verifyServerKey", ClientSession.class, SocketAddress.class,
                PublicKey.class);
        PublicKey key = Mockito.mock(PublicKey.class);
        Mockito.when(key.getAlgorithm()).thenReturn(getCurrentTestName());
        Mockito.when(key.getEncoded()).thenReturn(GenericUtils.EMPTY_BYTE_ARRAY);
        Mockito.when(key.getFormat()).thenReturn(getCurrentTestName());

        Object[] args = { Mockito.mock(ClientSession.class), new InetSocketAddress(TEST_LOCALHOST, 7365), key };
        Object[] invArgs = new Object[args.length];
        Random rnd = new Random(System.nanoTime());
        boolean expected = authenticator.isAccepted();
        for (int index = 0; index < Long.SIZE; index++) {
            for (int j = 0; j < args.length; j++) {
                if (rnd.nextBoolean()) {
                    invArgs[j] = args[j];
                } else {
                    invArgs[j] = null;
                }
            }

            Object result = method.invoke(authenticator, invArgs);
            assertTrue(result instanceof Boolean, "No boolean result");
            assertEquals("Mismatched result for " + Arrays.toString(invArgs), expected, ((Boolean) result).booleanValue());
        }
    }
}
