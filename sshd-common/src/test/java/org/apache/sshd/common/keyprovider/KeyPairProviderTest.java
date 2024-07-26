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
import java.util.Arrays;
import java.util.Map;
import java.util.function.Function;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class KeyPairProviderTest extends JUnitTestSupport {
    public KeyPairProviderTest() {
        super();
    }

    @Test
    void emptyKeyProvider() throws IOException, GeneralSecurityException {
        KeyPairProvider provider = KeyPairProvider.EMPTY_KEYPAIR_PROVIDER;
        assertTrue(GenericUtils.isEmpty(provider.loadKeys(null)), "Non empty loaded keys");
        assertTrue(GenericUtils.isEmpty(provider.getKeyTypes(null)), "Non empty key type");

        for (String keyType : new String[] { null, "", getCurrentTestName() }) {
            assertNull(provider.loadKey(null, keyType), "Unexpected key-pair loaded for type='" + keyType + "'");
        }
    }

    @Test
    void mapToKeyPairProvider() throws IOException, GeneralSecurityException {
        PublicKey pubKey = Mockito.mock(PublicKey.class);
        PrivateKey prvKey = Mockito.mock(PrivateKey.class);
        String[] testKeys = { getCurrentTestName(), getClass().getSimpleName() };
        Map<String, KeyPair> pairsMap = MapEntryUtils.toSortedMap(
                Arrays.asList(testKeys),
                Function.identity(),
                k -> new KeyPair(pubKey, prvKey),
                String.CASE_INSENSITIVE_ORDER);

        KeyPairProvider provider = MappedKeyPairProvider.MAP_TO_KEY_PAIR_PROVIDER.apply(pairsMap);
        assertEquals("Key types", pairsMap.keySet(), provider.getKeyTypes(null));
        assertEquals("Key pairs", pairsMap.values(), provider.loadKeys(null));

        for (Map.Entry<String, KeyPair> pe : pairsMap.entrySet()) {
            String keyType = pe.getKey();
            KeyPair expected = pe.getValue();
            KeyPair actual = provider.loadKey(null, keyType);
            assertSame(expected, actual, keyType);
        }
    }
}
