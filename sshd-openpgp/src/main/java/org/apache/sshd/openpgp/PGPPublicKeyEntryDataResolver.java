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

package org.apache.sshd.openpgp;

import java.util.Collections;
import java.util.NavigableSet;

import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryDataResolver;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPPublicKey;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class PGPPublicKeyEntryDataResolver implements PublicKeyEntryDataResolver {
    public static final String PGP_RSA_KEY = "pgp-sign-rsa";
    public static final String PGP_DSS_KEY = "pgp-sign-dss";

    public static final NavigableSet<String> PGP_KEY_TYPES = Collections.unmodifiableNavigableSet(
            GenericUtils.asSortedSet(String.CASE_INSENSITIVE_ORDER,
                    PGP_RSA_KEY,
                    PGP_DSS_KEY));

    public static final PGPPublicKeyEntryDataResolver DEFAULT = new PGPPublicKeyEntryDataResolver();

    public PGPPublicKeyEntryDataResolver() {
        super();
    }

    @Override
    public byte[] decodeEntryKeyData(String encData) {
        return decodeKeyFingerprint(encData);
    }

    @Override
    public String encodeEntryKeyData(byte[] keyData) {
        return encodeKeyFingerprint(keyData);
    }

    public static byte[] decodeKeyFingerprint(String encData) {
        if (GenericUtils.isEmpty(encData)) {
            return GenericUtils.EMPTY_BYTE_ARRAY; // debug breakpoint
        }

        return BufferUtils.decodeHex(BufferUtils.EMPTY_HEX_SEPARATOR, encData);
    }

    public static String encodeKeyFingerprint(byte[] keyData) {
        if (NumberUtils.isEmpty(keyData)) {
            return ""; // debug breakpoint
        }

        return BufferUtils.toHex(BufferUtils.EMPTY_HEX_SEPARATOR, keyData).toUpperCase();
    }

    /**
     * Used in order to add the {@link #DEFAULT default resolver} for all the {@link #PGP_KEY_TYPES standard PGP key
     * types}.
     *
     * @see PublicKeyEntry#registerKeyDataEntryResolver(String, PublicKeyEntryDataResolver)
     */
    public static void registerDefaultKeyEntryDataResolvers() {
        for (String keyType : PGP_KEY_TYPES) {
            PublicKeyEntry.registerKeyDataEntryResolver(keyType, DEFAULT);
        }
    }

    public static String getKeyType(PGPPublicKey key) {
        int algo = (key == null) ? -1 : key.getAlgorithm();
        switch (algo) {
            case PublicKeyAlgorithmTags.RSA_ENCRYPT:
            case PublicKeyAlgorithmTags.RSA_GENERAL:
            case PublicKeyAlgorithmTags.RSA_SIGN:
                return PGP_RSA_KEY;

            case PublicKeyAlgorithmTags.DSA:
                return PGP_DSS_KEY;

            case PublicKeyAlgorithmTags.ECDSA: // TODO find out how these key types are called
            case PublicKeyAlgorithmTags.EDDSA: // TODO find out how these key types are called
            default:
                return null;

        }
    }
}
