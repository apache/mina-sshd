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

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Random;

import org.apache.sshd.server.auth.password.AcceptAllPasswordAuthenticator;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.password.RejectAllPasswordAuthenticator;
import org.apache.sshd.server.auth.password.StaticPasswordAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class PasswordAuthenticatorTest extends BaseTestSupport {
    public PasswordAuthenticatorTest() {
        super();
    }

    @Test
    public void testAcceptAllPasswordAuthenticator() throws Exception {
        testStaticPasswordAuthenticator(AcceptAllPasswordAuthenticator.INSTANCE);
    }

    @Test
    public void testRejectAllPasswordAuthenticator() throws Exception {
        testStaticPasswordAuthenticator(RejectAllPasswordAuthenticator.INSTANCE);
    }

    private void testStaticPasswordAuthenticator(StaticPasswordAuthenticator authenticator) throws Exception {
        Method method = PasswordAuthenticator.class.getMethod("authenticate", String.class, String.class, ServerSession.class);
        Object[] args = { getCurrentTestName(), getClass().getName(), null /* ServerSession */ };
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
            assertTrue("No boolean result", result instanceof Boolean);
            assertEquals("Mismatched result for " + Arrays.toString(invArgs), expected, ((Boolean) result).booleanValue());
        }
    }
}
