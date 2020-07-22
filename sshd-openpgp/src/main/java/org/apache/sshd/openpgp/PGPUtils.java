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

import java.nio.file.Path;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.NavigableMap;
import java.util.Set;
import java.util.TreeMap;

import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.config.keys.IdentityUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.ValidateUtils;
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

    public static final String STD_LINUX_PGP_FOLDER_NAME = ".gnupg";
    public static final String STD_WINDOWS_PGP_FOLDER_NAME = "gnupg";

    /** Default MIME type for PGP encrypted files */
    public static final String PGP_ENCRYPTED_FILE = "application/pgp-encrypted";

    /** Alias for {@link EncryptionAlgorithm#Unencrypted Unencrypted} */
    public static final String NO_CIPHER_PLACEHOLDER = PropertyResolverUtils.NONE_VALUE;

    public static final Set<EncryptionAlgorithm> CIPHERS
            = Collections.unmodifiableSet(EnumSet.allOf(EncryptionAlgorithm.class));

    /** Alias for {@link CompressionAlgorithm#Uncompressed Uncompressed} */
    public static final String NO_COMPRESSION_PLACEHOLDER = PropertyResolverUtils.NONE_VALUE;

    public static final Set<CompressionAlgorithm> COMPRESSIONS
            = Collections.unmodifiableSet(EnumSet.allOf(CompressionAlgorithm.class));

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
     * @param  key                      The {@link Key} whose sub-keys to map - ignored if {@code null} or no sub-keys
     *                                  available
     * @return                          A {@link NavigableMap} where key=the (case <U>insensitive</U>) fingerprint
     *                                  value, value=the matching {@link Subkey}
     * @throws NullPointerException     If key with {@code null} fingerprint encountered
     * @throws IllegalArgumentException If key with empty fingerprint encountered
     * @throws IllegalStateException    If more than one key with same fingerprint found
     * @see                             #mapSubKeysByFingerprint(Collection)
     */
    public static NavigableMap<String, Subkey> mapSubKeysByFingerprint(Key key) {
        return mapSubKeysByFingerprint((key == null) ? Collections.emptyList() : key.getSubkeys());
    }

    /**
     * @param  subKeys                  The {@link Subkey}-s to map - ignored if {@code null}/empty
     * @return                          A {@link NavigableMap} where key=the (case <U>insensitive</U>) fingerprint
     *                                  value, value=the matching {@link Subkey}
     * @throws NullPointerException     If key with {@code null} fingerprint encountered
     * @throws IllegalArgumentException If key with empty fingerprint encountered
     * @throws IllegalStateException    If more than one key with same fingerprint found
     */
    public static NavigableMap<String, Subkey> mapSubKeysByFingerprint(Collection<? extends Subkey> subKeys) {
        if (GenericUtils.isEmpty(subKeys)) {
            return Collections.emptyNavigableMap();
        }

        NavigableMap<String, Subkey> keysMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (Subkey sk : subKeys) {
            String fp = ValidateUtils.checkNotNullAndNotEmpty(sk.getFingerprint(), "No fingerprint for %s", sk);
            Subkey prev = keysMap.put(fp, sk);
            ValidateUtils.checkState(prev == null, "Multiple sub-keys with fingerprint=%s: %s / %s", fp, sk, prev);
        }

        return keysMap;
    }

    /**
     * @param  key         The {@link Key} whose sub-keys to scan - ignored if {@code null} or has no sub-keys
     * @param  fingerprint The fingerprint to match (case <U>insensitive</U>) - ignored if {@code null}/empty
     * @return             The first matching {@link Subkey} - {@code null} if no match found
     * @see                #findSubkeyByFingerprint(Collection, String)
     */
    public static Subkey findSubkeyByFingerprint(Key key, String fingerprint) {
        return findSubkeyByFingerprint((key == null) ? Collections.emptyList() : key.getSubkeys(), fingerprint);
    }

    /**
     * @param  subKeys     The {@link Subkey}-s to scan - ignored if {@code null}/empty
     * @param  fingerprint The fingerprint to match (case <U>insensitive</U>) - ignored if {@code null}/empty
     * @return             The first matching sub-key - {@code null} if no match found
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

    private static final class LazyDefaultPgpKeysFolderHolder {
        private static final Path PATH = IdentityUtils.getUserHomeFolder()
                .resolve(OsUtils.isUNIX() ? STD_LINUX_PGP_FOLDER_NAME : STD_WINDOWS_PGP_FOLDER_NAME);

        private LazyDefaultPgpKeysFolderHolder() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }

    /**
     * @return The default <A HREF="https://www.gnupg.org/">Gnu Privacy Guard</A> folder used to hold key files.
     */
    @SuppressWarnings("synthetic-access")
    public static Path getDefaultPgpFolderPath() {
        return LazyDefaultPgpKeysFolderHolder.PATH;
    }

}
