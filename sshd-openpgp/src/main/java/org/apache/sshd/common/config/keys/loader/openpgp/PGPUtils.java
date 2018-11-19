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

package org.apache.sshd.common.config.keys.loader.openpgp;

import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import org.apache.sshd.common.util.GenericUtils;
import org.c02e.jpgpj.CompressionAlgorithm;
import org.c02e.jpgpj.EncryptionAlgorithm;
import org.c02e.jpgpj.Key;
import org.c02e.jpgpj.Subkey;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class PGPUtils {
    public static final String DEFAULT_PGP_FILE_SUFFIX = ".gpg";

    /** Default MIME type for PGP encrypted files */
    public static final String PGP_ENCRYPTED_FILE = "application/pgp-encrypted";

    /** Alias for {@link EncryptionAlgorithm#Unencrypted Unencrypted} */
    public static final String NO_CIPHER_PLACEHOLDER = "none";

    public static final Set<EncryptionAlgorithm> CIPHERS =
        Collections.unmodifiableSet(EnumSet.allOf(EncryptionAlgorithm.class));

    /** Alias for {@link CompressionAlgorithm#Uncompressed Uncompressed} */
    public static final String NO_COMPRESSION_PLACEHOLDER = "none";

    public static final Set<CompressionAlgorithm> COMPRESSIONS =
        Collections.unmodifiableSet(EnumSet.allOf(CompressionAlgorithm.class));

    private PGPUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    public static EncryptionAlgorithm fromCipherName(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }

        if (NO_CIPHER_PLACEHOLDER.equalsIgnoreCase(name)) {
            return EncryptionAlgorithm.Unencrypted;
        }

        return CIPHERS.stream()
            .filter(c -> name.equalsIgnoreCase(c.name()))
            .findFirst()
            .orElse(null);
    }

    public static CompressionAlgorithm fromCompressionName(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }

        if (NO_COMPRESSION_PLACEHOLDER.equalsIgnoreCase(name)) {
            return CompressionAlgorithm.Uncompressed;
        } else {
            return COMPRESSIONS.stream()
                .filter(c -> name.equalsIgnoreCase(c.name()))
                .findFirst()
                .orElse(null);
        }
    }

    /**
     * @param key The {@link Key} whose sub-keys to scan - ignored if {@code null} or has no sub-keys
     * @param fingerprint The fingerprint to match (case <U>insensitive</U>) - ignored if {@code null}/empty
     * @return The first matching {@link Subkey} - {@code null} if no match found
     * @see #findSubkeyByFingerprint(Collection, String)
     */
    public static Subkey findSubkeyByFingerprint(Key key, String fingerprint) {
        return findSubkeyByFingerprint((key == null) ? Collections.emptyList() : key.getSubkeys(), fingerprint);
    }

    /**
     * @param subKeys The {@link Subkey}-s to scan - ignored if {@code null}/empty
     * @param fingerprint The fingerprint to match (case <U>insensitive</U>) - ignored if {@code null}/empty
     * @return The first matching sub-key - {@code null} if no match found
     */
    public static Subkey findSubkeyByFingerprint(Collection<? extends Subkey> subKeys, String fingerprint) {
        if (GenericUtils.isEmpty(subKeys) || GenericUtils.isEmpty(fingerprint)) {
            return null;
        }

        return subKeys.stream()
            .filter(k -> fingerprint.equalsIgnoreCase(k.getFingerprint()))
            .findFirst()
            .orElse(null);
    }
}
