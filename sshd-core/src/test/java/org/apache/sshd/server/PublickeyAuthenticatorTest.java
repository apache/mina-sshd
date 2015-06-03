/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.server;

import java.lang.reflect.Method;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Random;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.PublickeyAuthenticator.StaticPublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.util.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class PublickeyAuthenticatorTest extends BaseTestSupport {
    public PublickeyAuthenticatorTest() {
        super();
    }

    @Test
    public void testAcceptAllPublickeyAuthenticator() throws Exception {
        testStaticPublickeyAuthenticator(PublickeyAuthenticator.AcceptAllPublickeyAuthenticator.INSTANCE);
    }

    @Test
    public void testRejectAllPublickeyAuthenticator() throws Exception {
        testStaticPublickeyAuthenticator(PublickeyAuthenticator.RejectAllPublickeyAuthenticator.INSTANCE);
    }

    private void testStaticPublickeyAuthenticator(StaticPublickeyAuthenticator authenticator) throws Exception {
        Method      method = PublickeyAuthenticator.class.getMethod("authenticate", String.class, PublicKey.class, ServerSession.class);
        PublicKey   key = Mockito.mock(PublicKey.class);
        Mockito.when(key.getAlgorithm()).thenReturn(getCurrentTestName());
        Mockito.when(key.getEncoded()).thenReturn(GenericUtils.EMPTY_BYTE_ARRAY);
        Mockito.when(key.getFormat()).thenReturn(getCurrentTestName());

        Object[]    args = { getCurrentTestName(),  key, null /* ServerSession */ };
        Object[]    invArgs = new Object[args.length];    
        Random      rnd = new Random(System.nanoTime());
        boolean     expected = authenticator.isAccepted();
        for (int index=0; index < Long.SIZE; index++) {
            for (int j=0; j < args.length; j++) {
                if (rnd.nextBoolean()) {
                    invArgs[j] = args[j];
                } else {
                    invArgs[j] = null;
                }
            }
            
            Object  result = method.invoke(authenticator, invArgs);
            assertTrue("No boolean result", result instanceof Boolean);
            assertEquals("Mismatched result for " + Arrays.toString(invArgs), expected, ((Boolean) result).booleanValue());
        }
    }
}
