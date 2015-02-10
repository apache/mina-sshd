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

package org.apache.sshd.common.util;

import java.util.ArrayList;
import java.util.EventListener;
import java.util.List;

import org.apache.sshd.util.BaseTest;
import org.junit.Assert;
import org.junit.Test;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class EventListenerUtilsTest extends BaseTest {
    public EventListenerUtilsTest() {
        super();
    }

    @Test
    public void testProxyWrapper() {
        List<ProxyListenerImpl> impls = new ArrayList<ProxyListenerImpl>();
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
            Assert.assertSame("Mismatched string at listener #" + index, expStr, l.getStringValue());
            Assert.assertSame("Mismatched number at listener #" + index, expNum, l.getNumberValue());
        }
    }

    private static interface ProxyListener extends EventListener {
        void callMeWithString(String s);

        void callMeWithNumber(Number n);
    }

    private static class ProxyListenerImpl implements ProxyListener {
        private String strValue;
        private Number numValue;

        public String getStringValue() {
            return strValue;
        }

        public void callMeWithString(String s) {
            strValue = s;
        }

        public Number getNumberValue() {
            return numValue;
        }

        public void callMeWithNumber(Number n) {
            numValue = n;
        }
    }
}
