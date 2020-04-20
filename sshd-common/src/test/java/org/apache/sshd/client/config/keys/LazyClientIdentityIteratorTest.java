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

package org.apache.sshd.client.config.keys;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class LazyClientIdentityIteratorTest extends JUnitTestSupport {
    public LazyClientIdentityIteratorTest() {
        super();
    }

    @Test
    public void testLazyKeysLoader() {
        List<CountingClientIdentityProvider> providers = new ArrayList<>();
        for (int index = 1; index <= Byte.SIZE; index++) {
            PublicKey pub = Mockito.mock(PublicKey.class);
            PrivateKey prv = Mockito.mock(PrivateKey.class);
            providers.add(new CountingClientIdentityProvider(new KeyPair(pub, prv)));
        }

        Iterable<KeyPair> ids = ClientIdentityProvider.lazyKeysLoader(
                providers, p -> {
                    try {
                        return p.getClientIdentities(null);
                    } catch (Exception e) {
                        throw new RuntimeException("Unexpected " + e.getClass().getSimpleName() + ": " + e.getMessage(), e);
                    }
                }, null);
        Iterator<KeyPair> keys = ids.iterator();

        for (int index = 0, count = providers.size(); index < count; index++) {
            CountingClientIdentityProvider p = providers.get(index);
            assertEquals("Mismatched provider #" + index + " pre-fetch load count", 0, p.getLoadCount());
            KeyPair expected = p.getKeyPair();

            assertTrue("No more keys after " + index + " values", keys.hasNext());
            KeyPair actual = keys.next();

            assertSame("Mismatched identity after " + index + " values", expected, actual);
            assertEquals("Mismatched provider #" + index + " post-fetch load count", 1, p.getLoadCount());
        }
    }

    static class CountingClientIdentityProvider implements ClientIdentityProvider {
        private final KeyPair kp;
        private int loadCount;

        CountingClientIdentityProvider(KeyPair kp) {
            this.kp = kp;
        }

        public int getLoadCount() {
            return loadCount;
        }

        public KeyPair getKeyPair() {
            return kp;
        }

        @Override
        public Iterable<KeyPair> getClientIdentities(SessionContext session) {
            loadCount++;
            return Collections.singletonList(getKeyPair());
        }

        @Override
        public String toString() {
            return getClass().getSimpleName()
                   + "[" + getKeyPair() + "]"
                   + ": loadCount=" + getLoadCount();
        }
    }
}
