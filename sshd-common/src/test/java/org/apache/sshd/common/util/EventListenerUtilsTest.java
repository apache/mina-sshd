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
public class EventListenerUtilsTest extends JUnitTestSupport {
    public EventListenerUtilsTest() {
        super();
    }

    @Test
    public void testProxyWrapper() {
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
            assertSame("Mismatched string at listener #" + index, expStr, l.getStringValue());
            assertSame("Mismatched number at listener #" + index, expNum, l.getNumberValue());
        }
    }

    @Test
    public void testListenerInstanceComparatorOnProxy() {
        Comparator<? super EventListener> comparator = EventListenerUtils.LISTENER_INSTANCE_COMPARATOR;
        ProxyListener p1
                = EventListenerUtils.proxyWrapper(ProxyListener.class, Collections.singletonList(new ProxyListenerImpl()));
        assertEquals("Mismatched self reference comparison", 0, comparator.compare(p1, p1));

        EventListener l = new EventListener() {
            /* nothing extra */ };
        assertEquals("Mismatched proxy vs. non-proxy result", 1, Integer.signum(comparator.compare(p1, l)));
        assertEquals("Mismatched non-proxy vs. proxy result", -1, Integer.signum(comparator.compare(l, p1)));

        ProxyListener p2
                = EventListenerUtils.proxyWrapper(ProxyListener.class, Collections.singletonList(new ProxyListenerImpl()));
        int p1vsp2 = Integer.signum(comparator.compare(p1, p2));
        assertNotEquals("Mismatched p1 vs. p2 comparison", 0, p1vsp2);
        assertEquals("Mismatched p2 vs. p1 comparison result", 0 - p1vsp2, Integer.signum(comparator.compare(p2, p1)));
    }

    @Test
    public void testListenerInstanceComparatorOnNonProxy() {
        Comparator<? super EventListener> comparator = EventListenerUtils.LISTENER_INSTANCE_COMPARATOR;
        EventListener l1 = new EventListener() {
            /* nothing extra */ };
        assertEquals("Mismatched self reference comparison", 0, comparator.compare(l1, l1));

        EventListener l2 = new EventListener() {
            /* nothing extra */ };
        int l1vsl2 = Integer.signum(comparator.compare(l1, l2));
        assertNotEquals("Mismatched l1 vs. l2 comparison result", 0, l1vsl2);
        assertEquals("Mismatched l2 vs. l1 comparison result", 0 - l1vsl2, Integer.signum(comparator.compare(l2, l1)));
    }

    @Test
    public void testSynchronizedListenersSetOnProxies() {
        ProxyListener p1
                = EventListenerUtils.proxyWrapper(ProxyListener.class, Collections.singletonList(new ProxyListenerImpl()));
        Set<ProxyListener> s = EventListenerUtils.synchronizedListenersSet();
        for (int index = 1; index <= Byte.SIZE; index++) {
            boolean modified = s.add(p1);
            assertEquals("Mismatched p1 modification indicator at attempt #" + index, index == 1, modified);
            assertEquals("Mismatched p1 set size at attempt #" + index, 1, s.size());
        }

        ProxyListener p2
                = EventListenerUtils.proxyWrapper(ProxyListener.class, Collections.singletonList(new ProxyListenerImpl()));
        for (int index = 1; index <= Byte.SIZE; index++) {
            boolean modified = s.add(p2);
            assertEquals("Mismatched p2 modification indicator at attempt #" + index, index == 1, modified);
            assertEquals("Mismatched p2 set size at attempt #" + index, 2, s.size());
        }

        assertTrue("Failed to remove p1", s.remove(p1));
        assertEquals("Mismatched post p1-remove size", 1, s.size());
        assertTrue("Failed to remove p2", s.remove(p2));
        assertEquals("Mismatched post p2-remove size", 0, s.size());
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
