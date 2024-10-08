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

package org.apache.sshd.common.keyprovider;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
public class MultiKeyIdentityProviderTest extends JUnitTestSupport {
    public MultiKeyIdentityProviderTest() {
        super();
    }

    // see SSHD-860
    @Test
    void lazyKeyIdentityMultiProvider() throws IOException, GeneralSecurityException {
        List<KeyPair> expected = new ArrayList<>();
        for (int index = 1; index <= Short.SIZE; index++) {
            PublicKey pub = Mockito.mock(PublicKey.class);
            PrivateKey prv = Mockito.mock(PrivateKey.class);
            expected.add(new KeyPair(pub, prv));
        }

        Collection<KeyIdentityProvider> providers = new ArrayList<>();
        AtomicInteger position = new AtomicInteger(0);
        for (int startIndex = 0, count = expected.size(), slice = count / 3; startIndex < count;) {
            int nextIndex = Math.min(count, startIndex + slice);
            Collection<KeyPair> keys = expected.subList(startIndex, nextIndex);
            providers.add(wrapKeyPairs(position, keys));
            startIndex = nextIndex;
        }

        KeyIdentityProvider multiProvider = KeyIdentityProvider.multiProvider(providers);
        assertObjectInstanceOf(MultiKeyIdentityProvider.class.getSimpleName(), MultiKeyIdentityProvider.class, multiProvider);

        Iterable<KeyPair> keys = multiProvider.loadKeys(null);
        Iterator<KeyPair> iter = keys.iterator();
        for (int index = 0, count = expected.size(); index < count; index++) {
            KeyPair kpExpected = expected.get(index);
            assertTrue(iter.hasNext(), "Premature keys exhaustion after " + index + " iterations");
            KeyPair kpActual = iter.next();
            assertSame(kpExpected, kpActual, "Mismatched key at index=" + index);
            assertEquals(index + 1, position.get(), "Mismatched requested lazy key position");
        }

        assertFalse(iter.hasNext(), "Not all keys exhausted");
    }

    private static KeyIdentityProvider wrapKeyPairs(AtomicInteger position, Iterable<KeyPair> keys) {
        return new KeyIdentityProvider() {
            @Override
            public Iterable<KeyPair> loadKeys(SessionContext session) {
                return new Iterable<KeyPair>() {
                    @Override
                    public Iterator<KeyPair> iterator() {
                        return new Iterator<KeyPair>() {
                            private final Iterator<KeyPair> iter = keys.iterator();

                            @Override
                            public boolean hasNext() {
                                return iter.hasNext();
                            }

                            @Override
                            public KeyPair next() {
                                position.incrementAndGet();
                                return iter.next();
                            }
                        };
                    }
                };
            }
        };
    }
}
