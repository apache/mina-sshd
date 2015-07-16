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

package org.apache.sshd.common.keyprovider;

import java.security.KeyPair;
import java.util.Map;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Transformer;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Holds a {@link Map} of {@link String}-&gt;{@link KeyPair} where the map key
 * is the type and value is the associated {@link KeyPair}
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class MappedKeyPairProvider implements KeyPairProvider {
    /**
     * Transforms a {@link Map} of {@link String}-&gt;{@link KeyPair} to a
     * {@link KeyPairProvider} where map key is the type and value is the
     * associated {@link KeyPair}
     */
    public static final Transformer<Map<String,KeyPair>, KeyPairProvider> MAP_TO_KEY_PAIR_PROVIDER =
        new Transformer<Map<String,KeyPair>, KeyPairProvider>() {
            @Override
            public KeyPairProvider transform(final Map<String, KeyPair> input) {
                return new MappedKeyPairProvider(input);
            }
        };

    private final Map<String,KeyPair>   pairsMap;

    public MappedKeyPairProvider(Map<String,KeyPair> pairsMap) {
        this.pairsMap = ValidateUtils.checkNotNull(pairsMap, "No pairs map provided");
    }

    @Override
    public Iterable<KeyPair> loadKeys() {
        return pairsMap.values();
    }
    
    @Override
    public KeyPair loadKey(String type) {
        return pairsMap.get(type);
    }
    
    @Override
    public Iterable<String> getKeyTypes() {
        return pairsMap.keySet();
    }

    @Override
    public String toString() {
        return String.valueOf(getKeyTypes());
    }
}
