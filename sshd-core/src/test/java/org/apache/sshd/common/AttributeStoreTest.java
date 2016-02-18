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

package org.apache.sshd.common;

import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.AttributeStore.AttributeKey;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AttributeStoreTest extends BaseTestSupport {
    private static final AttributeKey<String> KEY = new AttributeKey<>();

    public AttributeStoreTest() {
        super();
    }

    @Test
    public void testResolveFactoryManagerAttribute() {
        assertNull("Unexpected null factory value", AttributeStore.Utils.resolveAttribute((FactoryManager) null, KEY));

        FactoryManager manager = Mockito.mock(FactoryManager.class);
        String expected = setAttributeValue(manager, getCurrentTestName());
        assertSame("Mismatched resolved value", expected, AttributeStore.Utils.resolveAttribute(manager, KEY));
    }

    @Test
    public void testResolveSessionAttribute() {
        assertNull("Unexpected null session value", AttributeStore.Utils.resolveAttribute((Session) null, KEY));

        Session session = Mockito.mock(Session.class);
        final AtomicInteger managerCount = new AtomicInteger(0);
        Mockito.when(session.getFactoryManager()).then(new Answer<FactoryManager>() {
            @Override
            public FactoryManager answer(InvocationOnMock invocation) throws Throwable {
                managerCount.incrementAndGet();
                return null;
            }
        });
        setAttributeValue(session, null);
        assertNull("Unexpected success for empty attribute", AttributeStore.Utils.resolveAttribute(session, KEY));
        assertEquals("Factory manager not requested", 1, managerCount.getAndSet(0));

        String expected = setAttributeValue(session, getCurrentTestName());
        assertSame("Mismatched attribute value", expected, AttributeStore.Utils.resolveAttribute(session, KEY));
        assertEquals("Unexpected manager request", 0, managerCount.get());
    }

    @Test
    public void testResolveChannelAttribute() {
        assertNull("Unexpected null channek value", AttributeStore.Utils.resolveAttribute((Channel) null, KEY));

        final Session session = Mockito.mock(Session.class);
        final AtomicInteger managerCount = new AtomicInteger(0);
        Mockito.when(session.getFactoryManager()).thenAnswer(new Answer<FactoryManager>() {
            @Override
            public FactoryManager answer(InvocationOnMock invocation) throws Throwable {
                managerCount.incrementAndGet();
                return null;
            }
        });
        setAttributeValue(session, null);

        Channel channel = Mockito.mock(Channel.class);
        final AtomicInteger sessionCount = new AtomicInteger(0);
        Mockito.when(channel.getSession()).thenAnswer(new Answer<Session>() {
            @Override
            public Session answer(InvocationOnMock invocation) throws Throwable {
                sessionCount.incrementAndGet();
                return session;
            }
        });
        setAttributeValue(channel, null);

        assertNull("Unexpected success for empty attribute", AttributeStore.Utils.resolveAttribute(channel, KEY));
        assertEquals("Session not requested", 1, sessionCount.getAndSet(0));
        assertEquals("Factory manager not requested", 1, managerCount.getAndSet(0));

        String expected = setAttributeValue(channel, getCurrentTestName());
        assertSame("Mismatched attribute value", expected, AttributeStore.Utils.resolveAttribute(channel, KEY));
        assertEquals("Unexpected session request", 0, sessionCount.get());
        assertEquals("Unexpected manager request", 0, managerCount.get());
    }

    private static String setAttributeValue(AttributeStore store, String value) {
        Mockito.when(store.getAttribute(Matchers.eq(KEY))).thenReturn(value);
        return value;
    }
}
