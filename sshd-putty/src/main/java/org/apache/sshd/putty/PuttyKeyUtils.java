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

package org.apache.sshd.putty;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.NavigableMap;
import java.util.TreeMap;

import org.apache.sshd.common.config.keys.loader.KeyPairResourceParser;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class PuttyKeyUtils {
    public static final List<PuttyKeyPairResourceParser<?, ?>> DEFAULT_PARSERS;

    public static final NavigableMap<String, PuttyKeyPairResourceParser<?, ?>> BY_KEY_TYPE;

    public static final KeyPairResourceParser DEFAULT_INSTANCE;

    static {
        List<PuttyKeyPairResourceParser<?, ?>> parsers = new ArrayList<>();
        parsers.add(RSAPuttyKeyDecoder.INSTANCE);
        parsers.add(DSSPuttyKeyDecoder.INSTANCE);
        if (SecurityUtils.isECCSupported()) {
            parsers.add(ECDSAPuttyKeyDecoder.INSTANCE);
        }
        if (SecurityUtils.isEDDSACurveSupported()) {
            parsers.add(EdDSAPuttyKeyDecoder.INSTANCE);
        }
        NavigableMap<String, PuttyKeyPairResourceParser<?, ?>> map = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (PuttyKeyPairResourceParser<?, ?> p : parsers) {
            Collection<String> supported = p.getSupportedKeyTypes();
            for (String k : supported) {
                map.put(k, p);
            }
        }
        DEFAULT_PARSERS = Collections.unmodifiableList(parsers);
        BY_KEY_TYPE = Collections.unmodifiableNavigableMap(map);
        DEFAULT_INSTANCE = KeyPairResourceParser.aggregate(parsers);
    }

    private PuttyKeyUtils() {
        throw new UnsupportedOperationException("No instance");
    }
}
