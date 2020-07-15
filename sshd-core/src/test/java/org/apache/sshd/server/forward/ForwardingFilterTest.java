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

package org.apache.sshd.server.forward;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ForwardingFilterTest extends BaseTestSupport {
    public ForwardingFilterTest() {
        super();
    }

    @Test
    public void testFromStringForwardingFilterType() {
        for (String name : new String[] { null, "", getCurrentTestName() }) {
            assertNull("Unexpected value for name='" + name + "'", ForwardingFilter.Type.fromString(name));
        }

        for (ForwardingFilter.Type expected : ForwardingFilter.Type.VALUES) {
            for (String name : new String[] { expected.name(), expected.getName() }) {
                for (int index = 0; index < name.length(); index++) {
                    ForwardingFilter.Type actual = ForwardingFilter.Type.fromString(name);
                    assertSame("Mismatched instance for name=" + name, expected, actual);
                    name = shuffleCase(name); // prepare for next iteration
                }
            }
        }
    }

    @Test
    public void testAcceptAllForwardingFilter() {
        testStaticDecisionForwardingFilter(AcceptAllForwardingFilter.INSTANCE, true);
    }

    @Test
    public void testRejectAllForwardingFilter() {
        testStaticDecisionForwardingFilter(RejectAllForwardingFilter.INSTANCE, false);
    }

    private static void testStaticDecisionForwardingFilter(StaticDecisionForwardingFilter filter, boolean expected) {
        assertEquals("Mismatched acceptance status", expected, filter.isAccepted());

        Session session = Mockito.mock(Session.class);
        assertEquals("Mismatched 'canForwardAgent' result", expected, filter.canForwardAgent(session, "auth-agent-req"));
        assertEquals("Mismatched 'canForwardX11' result", expected, filter.canForwardX11(session, "x11-req"));
        assertEquals("Mismatched 'canListen' result", expected, filter.canListen(SshdSocketAddress.LOCALHOST_ADDRESS, session));

        for (ForwardingFilter.Type t : ForwardingFilter.Type.VALUES) {
            assertEquals("Mismatched 'canConnect(" + t + ")' result", expected,
                    filter.canConnect(t, SshdSocketAddress.LOCALHOST_ADDRESS, session));
        }
    }
}
