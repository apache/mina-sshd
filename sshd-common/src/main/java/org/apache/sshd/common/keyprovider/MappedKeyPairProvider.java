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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Function;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Holds a {@link Map} of {@link String}-&gt;{@link KeyPair} where the map key is the type and value is the associated
 * {@link KeyPair}
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class MappedKeyPairProvider implements KeyPairProvider {
    /**
     * Transforms a {@link Map} of {@link String}-&gt;{@link KeyPair} to a {@link KeyPairProvider} where map key is the
     * type and value is the associated {@link KeyPair}
     */
    public static final Function<Map<String, KeyPair>, KeyPairProvider> MAP_TO_KEY_PAIR_PROVIDER = MappedKeyPairProvider::new;

    private final Map<String, KeyPair> pairsMap;

    public MappedKeyPairProvider(KeyPair... pairs) {
        this(GenericUtils.isEmpty(pairs) ? Collections.emptyList() : Arrays.asList(pairs));
    }

    public MappedKeyPairProvider(Collection<? extends KeyPair> pairs) {
        this(mapUniquePairs(pairs));
    }

    public MappedKeyPairProvider(Map<String, KeyPair> pairsMap) {
        this.pairsMap = ValidateUtils.checkNotNullAndNotEmpty(pairsMap, "No pairs map provided");
    }

    @Override
    public Iterable<KeyPair> loadKeys(SessionContext session) {
        return pairsMap.values();
    }

    @Override
    public KeyPair loadKey(SessionContext session, String type) {
        return pairsMap.get(type);
    }

    @Override
    public Iterable<String> getKeyTypes(SessionContext session) {
        return pairsMap.keySet();
    }

    @Override
    public String toString() {
        return String.valueOf(pairsMap.keySet());
    }

    public static Map<String, KeyPair> mapUniquePairs(Collection<? extends KeyPair> pairs) {
        if (GenericUtils.isEmpty(pairs)) {
            return Collections.emptyMap();
        }

        Map<String, KeyPair> pairsMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (KeyPair kp : pairs) {
            String keyType = ValidateUtils.checkNotNullAndNotEmpty(KeyUtils.getKeyType(kp), "Cannot determine key type");
            KeyPair prev = pairsMap.put(keyType, kp);
            ValidateUtils.checkTrue(prev == null, "Multiple keys of type=%s", keyType);
        }

        return pairsMap;
    }
}
