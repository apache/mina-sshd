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

package org.apache.sshd.common.config.keys.loader.pem;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.loader.KeyPairResourceParser;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class PEMResourceParserUtils {
    public static final KeyPairResourceParser PROXY = new KeyPairResourceParser() {
        @Override
        public Collection<KeyPair> loadKeyPairs(
                SessionContext session, NamedResource resourceKey, FilePasswordProvider passwordProvider, List<String> lines)
                throws IOException, GeneralSecurityException {
            @SuppressWarnings("synthetic-access")
            KeyPairResourceParser proxy = PROXY_HOLDER.get();
            return (proxy == null)
                    ? Collections.emptyList() : proxy.loadKeyPairs(session, resourceKey, passwordProvider, lines);
        }

        @Override
        public boolean canExtractKeyPairs(NamedResource resourceKey, List<String> lines)
                throws IOException, GeneralSecurityException {
            @SuppressWarnings("synthetic-access")
            KeyPairResourceParser proxy = PROXY_HOLDER.get();
            return (proxy != null) && proxy.canExtractKeyPairs(resourceKey, lines);
        }
    };

    private static final Map<String, KeyPairPEMResourceParser> BY_OID_MAP = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    private static final Map<String, KeyPairPEMResourceParser> BY_ALGORITHM_MAP = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    private static final AtomicReference<KeyPairResourceParser> PROXY_HOLDER
            = new AtomicReference<>(KeyPairResourceParser.EMPTY);

    static {
        registerPEMResourceParser(RSAPEMResourceKeyPairParser.INSTANCE);
        registerPEMResourceParser(DSSPEMResourceKeyPairParser.INSTANCE);
        registerPEMResourceParser(ECDSAPEMResourceKeyPairParser.INSTANCE);
        registerPEMResourceParser(PKCS8PEMResourceKeyPairParser.INSTANCE);
    }

    private PEMResourceParserUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    public static void registerPEMResourceParser(KeyPairPEMResourceParser parser) {
        Objects.requireNonNull(parser, "No parser to register");
        synchronized (BY_OID_MAP) {
            BY_OID_MAP.put(ValidateUtils.checkNotNullAndNotEmpty(parser.getAlgorithmIdentifier(), "No OID value"), parser);
        }

        synchronized (BY_ALGORITHM_MAP) {
            BY_ALGORITHM_MAP.put(ValidateUtils.checkNotNullAndNotEmpty(parser.getAlgorithm(), "No algorithm value"), parser);
            // Use a copy in order to avoid concurrent modifications
            PROXY_HOLDER.set(KeyPairResourceParser.aggregate(new ArrayList<>(BY_ALGORITHM_MAP.values())));
        }
    }

    public static KeyPairPEMResourceParser getPEMResourceParserByOidValues(Collection<? extends Number> oid) {
        return getPEMResourceParserByOid(GenericUtils.join(oid, '.'));
    }

    public static KeyPairPEMResourceParser getPEMResourceParserByOid(String oid) {
        if (GenericUtils.isEmpty(oid)) {
            return null;
        }

        synchronized (BY_OID_MAP) {
            return BY_OID_MAP.get(oid);
        }
    }

    public static KeyPairPEMResourceParser getPEMResourceParserByAlgorithm(String algorithm) {
        if (GenericUtils.isEmpty(algorithm)) {
            return null;
        }

        synchronized (BY_ALGORITHM_MAP) {
            return BY_ALGORITHM_MAP.get(algorithm);
        }
    }
}
