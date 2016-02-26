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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.TreeMap;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class KeyPairProviderTest extends BaseTestSupport {
    public KeyPairProviderTest() {
        super();
    }

    @Test
    public void testEmptyKeyProvider() {
        KeyPairProvider provider = KeyPairProvider.EMPTY_KEYPAIR_PROVIDER;
        assertTrue("Non empty loaded keys", GenericUtils.isEmpty(provider.loadKeys()));
        assertTrue("Non empty key type", GenericUtils.isEmpty(provider.getKeyTypes()));

        for (String keyType : new String[]{null, "", getCurrentTestName()}) {
            assertNull("Unexpected key-pair loaded for type='" + keyType + "'", provider.loadKey(keyType));
        }
    }

    @Test
    public void testMapToKeyPairProvider() {
        final PublicKey pubKey = Mockito.mock(PublicKey.class);
        final PrivateKey prvKey = Mockito.mock(PrivateKey.class);
        final String[] testKeys = {getCurrentTestName(), getClass().getSimpleName()};
        Map<String, KeyPair> pairsMap = new TreeMap<String, KeyPair>(String.CASE_INSENSITIVE_ORDER) {
            private static final long serialVersionUID = 1L;    // we're not serializing it

            {
                for (String keyType : testKeys) {
                    put(keyType, new KeyPair(pubKey, prvKey));
                }
            }
        };
        KeyPairProvider provider = MappedKeyPairProvider.MAP_TO_KEY_PAIR_PROVIDER.transform(pairsMap);
        assertEquals("Key types", pairsMap.keySet(), provider.getKeyTypes());
        assertEquals("Key pairs", pairsMap.values(), provider.loadKeys());

        for (Map.Entry<String, KeyPair> pairEntry : pairsMap.entrySet()) {
            String keyType = pairEntry.getKey();
            KeyPair expected = pairEntry.getValue();
            KeyPair actual = provider.loadKey(keyType);
            assertSame(keyType, expected, actual);
        }
    }
}
