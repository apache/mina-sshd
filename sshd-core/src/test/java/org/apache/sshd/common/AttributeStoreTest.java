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

import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class AttributeStoreTest extends BaseTestSupport {
    private static final AttributeRepository.AttributeKey<String> KEY = new AttributeRepository.AttributeKey<>();

    public AttributeStoreTest() {
        super();
    }

    @Test
    void resolveFactoryManagerAttribute() {
        assertNull(FactoryManager.resolveAttribute((FactoryManager) null, KEY), "Unexpected null factory value");

        FactoryManager manager = Mockito.mock(FactoryManager.class);
        String expected = setAttributeValue(manager, getCurrentTestName());
        assertSame(expected, FactoryManager.resolveAttribute(manager, KEY), "Mismatched resolved value");
    }

    @Test
    void resolveSessionAttribute() {
        assertNull(Session.resolveAttribute((Session) null, KEY), "Unexpected null session value");

        Session session = Mockito.mock(Session.class);
        AtomicInteger managerCount = new AtomicInteger(0);
        Mockito.when(session.getFactoryManager()).then(invocation -> {
            managerCount.incrementAndGet();
            return null;
        });
        setAttributeValue(session, null);
        assertNull(Session.resolveAttribute(session, KEY), "Unexpected success for empty attribute");
        assertEquals(1, managerCount.getAndSet(0), "Factory manager not requested");

        String expected = setAttributeValue(session, getCurrentTestName());
        assertSame(expected, Session.resolveAttribute(session, KEY), "Mismatched attribute value");
        assertEquals(0, managerCount.get(), "Unexpected manager request");
    }

    @Test
    void resolveChannelAttribute() {
        assertNull(Channel.resolveAttribute((Channel) null, KEY), "Unexpected null channek value");

        Session session = Mockito.mock(Session.class);
        AtomicInteger managerCount = new AtomicInteger(0);
        Mockito.when(session.getFactoryManager()).thenAnswer(invocation -> {
            managerCount.incrementAndGet();
            return null;
        });
        setAttributeValue(session, null);

        Channel channel = Mockito.mock(Channel.class);
        AtomicInteger sessionCount = new AtomicInteger(0);
        Mockito.when(channel.getSession()).thenAnswer(invocation -> {
            sessionCount.incrementAndGet();
            return session;
        });
        setAttributeValue(channel, null);

        assertNull(Channel.resolveAttribute(channel, KEY), "Unexpected success for empty attribute");
        assertEquals(1, sessionCount.getAndSet(0), "Session not requested");
        assertEquals(1, managerCount.getAndSet(0), "Factory manager not requested");

        String expected = setAttributeValue(channel, getCurrentTestName());
        assertSame(expected, Channel.resolveAttribute(channel, KEY), "Mismatched attribute value");
        assertEquals(0, sessionCount.get(), "Unexpected session request");
        assertEquals(0, managerCount.get(), "Unexpected manager request");
    }

    private static String setAttributeValue(AttributeStore store, String value) {
        Mockito.when(store.getAttribute(ArgumentMatchers.eq(KEY))).thenReturn(value);
        return value;
    }
}
