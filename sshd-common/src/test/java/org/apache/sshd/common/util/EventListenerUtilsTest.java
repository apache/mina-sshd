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

package org.apache.sshd.common.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EventListener;
import java.util.List;
import java.util.Set;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class EventListenerUtilsTest extends JUnitTestSupport {
    public EventListenerUtilsTest() {
        super();
    }

    @Test
    void proxyWrapper() {
        List<ProxyListenerImpl> impls = new ArrayList<>();
        for (int index = 0; index < Byte.SIZE; index++) {
            impls.add(new ProxyListenerImpl());
        }

        ProxyListener listener = EventListenerUtils.proxyWrapper(ProxyListener.class, impls);
        String expStr = getCurrentTestName();
        Number expNum = System.currentTimeMillis();
        listener.callMeWithString(expStr);
        listener.callMeWithNumber(expNum);

        for (int index = 0; index < impls.size(); index++) {
            ProxyListenerImpl l = impls.get(index);
            assertSame(expStr, l.getStringValue(), "Mismatched string at listener #" + index);
            assertSame(expNum, l.getNumberValue(), "Mismatched number at listener #" + index);
        }
    }

    @Test
    void listenerInstanceComparatorOnProxy() {
        Comparator<? super EventListener> comparator = EventListenerUtils.LISTENER_INSTANCE_COMPARATOR;
        ProxyListener p1
                = EventListenerUtils.proxyWrapper(ProxyListener.class, Collections.singletonList(new ProxyListenerImpl()));
        assertEquals(0, comparator.compare(p1, p1), "Mismatched self reference comparison");

        EventListener l = new EventListener() {
            /* nothing extra */ };
        assertEquals(1, Integer.signum(comparator.compare(p1, l)), "Mismatched proxy vs. non-proxy result");
        assertEquals(-1, Integer.signum(comparator.compare(l, p1)), "Mismatched non-proxy vs. proxy result");

        ProxyListener p2
                = EventListenerUtils.proxyWrapper(ProxyListener.class, Collections.singletonList(new ProxyListenerImpl()));
        int p1vsp2 = Integer.signum(comparator.compare(p1, p2));
        assertNotEquals(0, p1vsp2, "Mismatched p1 vs. p2 comparison");
        assertEquals(0 - p1vsp2, Integer.signum(comparator.compare(p2, p1)), "Mismatched p2 vs. p1 comparison result");
    }

    @Test
    void listenerInstanceComparatorOnNonProxy() {
        Comparator<? super EventListener> comparator = EventListenerUtils.LISTENER_INSTANCE_COMPARATOR;
        EventListener l1 = new EventListener() {
            /* nothing extra */ };
        assertEquals(0, comparator.compare(l1, l1), "Mismatched self reference comparison");

        EventListener l2 = new EventListener() {
            /* nothing extra */ };
        int l1vsl2 = Integer.signum(comparator.compare(l1, l2));
        assertNotEquals(0, l1vsl2, "Mismatched l1 vs. l2 comparison result");
        assertEquals(0 - l1vsl2, Integer.signum(comparator.compare(l2, l1)), "Mismatched l2 vs. l1 comparison result");
    }

    @Test
    void synchronizedListenersSetOnProxies() {
        ProxyListener p1
                = EventListenerUtils.proxyWrapper(ProxyListener.class, Collections.singletonList(new ProxyListenerImpl()));
        Set<ProxyListener> s = EventListenerUtils.synchronizedListenersSet();
        for (int index = 1; index <= Byte.SIZE; index++) {
            boolean modified = s.add(p1);
            assertEquals("Mismatched p1 modification indicator at attempt #" + index, index == 1, modified);
            assertEquals(1, s.size(), "Mismatched p1 set size at attempt #" + index);
        }

        ProxyListener p2
                = EventListenerUtils.proxyWrapper(ProxyListener.class, Collections.singletonList(new ProxyListenerImpl()));
        for (int index = 1; index <= Byte.SIZE; index++) {
            boolean modified = s.add(p2);
            assertEquals("Mismatched p2 modification indicator at attempt #" + index, index == 1, modified);
            assertEquals(2, s.size(), "Mismatched p2 set size at attempt #" + index);
        }

        assertTrue(s.remove(p1), "Failed to remove p1");
        assertEquals(1, s.size(), "Mismatched post p1-remove size");
        assertTrue(s.remove(p2), "Failed to remove p2");
        assertEquals(0, s.size(), "Mismatched post p2-remove size");
    }

    interface ProxyListener extends SshdEventListener {
        void callMeWithString(String s);

        void callMeWithNumber(Number n);
    }

    static class ProxyListenerImpl implements ProxyListener {
        private String strValue;
        private Number numValue;

        ProxyListenerImpl() {
            super();
        }

        public String getStringValue() {
            return strValue;
        }

        @Override
        public void callMeWithString(String s) {
            strValue = s;
        }

        public Number getNumberValue() {
            return numValue;
        }

        @Override
        public void callMeWithNumber(Number n) {
            numValue = n;
        }
    }
}
