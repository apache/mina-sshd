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

package org.apache.sshd.server;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.auth.pubkey.AcceptAllPublickeyAuthenticator;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.auth.pubkey.RejectAllPublickeyAuthenticator;
import org.apache.sshd.server.auth.pubkey.StaticPublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class PublickeyAuthenticatorTest extends BaseTestSupport {
    public PublickeyAuthenticatorTest() {
        super();
    }

    @Test
    public void testAcceptAllPublickeyAuthenticator() throws Throwable {
        testStaticPublickeyAuthenticator(AcceptAllPublickeyAuthenticator.INSTANCE);
    }

    @Test
    public void testRejectAllPublickeyAuthenticator() throws Throwable {
        testStaticPublickeyAuthenticator(RejectAllPublickeyAuthenticator.INSTANCE);
    }

    private void testStaticPublickeyAuthenticator(StaticPublickeyAuthenticator authenticator) throws Throwable {
        Method method
                = PublickeyAuthenticator.class.getMethod("authenticate", String.class, PublicKey.class, ServerSession.class);
        RSAPublicKey key = Mockito.mock(RSAPublicKey.class);
        Mockito.when(key.getAlgorithm()).thenReturn(getCurrentTestName());
        Mockito.when(key.getEncoded()).thenReturn(GenericUtils.EMPTY_BYTE_ARRAY);
        Mockito.when(key.getFormat()).thenReturn(getCurrentTestName());
        Mockito.when(key.getModulus()).thenReturn(BigInteger.TEN);
        Mockito.when(key.getPublicExponent()).thenReturn(BigInteger.ONE);

        ServerSession session = Mockito.mock(ServerSession.class);
        Object[] invArgs = new Object[] { null /* username */, null /* key */, null /* server session */ };
        boolean expected = authenticator.isAccepted();
        boolean[] flags = new boolean[] { false, true };
        for (boolean useUsername : flags) {
            invArgs[0] = useUsername ? getCurrentTestName() : null;

            for (boolean useKey : flags) {
                invArgs[1] = useKey ? key : null;

                for (boolean useSession : flags) {
                    invArgs[2] = useSession ? session : null;

                    Object result;
                    try {
                        result = method.invoke(authenticator, invArgs);
                    } catch (InvocationTargetException e) {
                        Throwable t = e.getTargetException(); // peel of the real exception
                        System.err.println("Failed (" + t.getClass().getSimpleName() + ")"
                                           + " to invoke with user=" + useUsername
                                           + ", key=" + useKey
                                           + ", session=" + useSession
                                           + ": " + t.getMessage());
                        throw t;
                    }

                    assertTrue("No boolean result", result instanceof Boolean);
                    assertEquals("Mismatched result for " + Arrays.toString(invArgs), expected,
                            ((Boolean) result).booleanValue());
                }
            }
        }
    }
}
