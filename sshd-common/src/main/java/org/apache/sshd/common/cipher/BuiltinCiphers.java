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

package org.apache.sshd.common.cipher;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.NamedFactoriesListParseResult;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Provides easy access to the currently implemented ciphers
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum BuiltinCiphers implements CipherFactory {
    none(Constants.NONE, 0, 0, 0, "None", 0, "None", 0) {
        @Override
        public Cipher create() {
            return new CipherNone();
        }
    },
    aes128cbc(Constants.AES128_CBC, 16, 0, 16, "AES", 128, "AES/CBC/NoPadding", 16),
    aes128ctr(Constants.AES128_CTR, 16, 0, 16, "AES", 128, "AES/CTR/NoPadding", 16),
    aes128gcm(Constants.AES128_GCM, 12, 16, 16, "AES", 128, "AES/GCM/NoPadding", 16) {
        @Override
        public Cipher create() {
            return new BaseGCMCipher(
                    getIVSize(), getAuthenticationTagSize(), getKdfSize(), getAlgorithm(),
                    getKeySize(), getTransformation(), getCipherBlockSize());
        }
    },
    aes256gcm(Constants.AES256_GCM, 12, 16, 32, "AES", 256, "AES/GCM/NoPadding", 16) {
        @Override
        public Cipher create() {
            return new BaseGCMCipher(
                    getIVSize(), getAuthenticationTagSize(), getKdfSize(), getAlgorithm(),
                    getKeySize(), getTransformation(), getCipherBlockSize());
        }
    },
    aes192cbc(Constants.AES192_CBC, 16, 0, 24, "AES", 192, "AES/CBC/NoPadding", 16),
    aes192ctr(Constants.AES192_CTR, 16, 0, 24, "AES", 192, "AES/CTR/NoPadding", 16),
    aes256cbc(Constants.AES256_CBC, 16, 0, 32, "AES", 256, "AES/CBC/NoPadding", 16),
    aes256ctr(Constants.AES256_CTR, 16, 0, 32, "AES", 256, "AES/CTR/NoPadding", 16),
    /**
     * @deprecated
     * @see        <A HREF="https://issues.apache.org/jira/browse/SSHD-1004">SSHD-1004</A>
     */
    @Deprecated
    arcfour128(Constants.ARCFOUR128, 8, 0, 16, "ARCFOUR", 128, "RC4", 16) {
        @Override
        public Cipher create() {
            return new BaseRC4Cipher(getIVSize(), getKdfSize(), getKeySize(), getCipherBlockSize());
        }
    },
    /**
     * @deprecated
     * @see        <A HREF="https://issues.apache.org/jira/browse/SSHD-1004">SSHD-1004</A>
     */
    @Deprecated
    arcfour256(Constants.ARCFOUR256, 8, 0, 32, "ARCFOUR", 256, "RC4", 32) {
        @Override
        public Cipher create() {
            return new BaseRC4Cipher(getIVSize(), getKdfSize(), getKeySize(), getCipherBlockSize());
        }
    },
    /**
     * @deprecated
     * @see        <A HREF="https://issues.apache.org/jira/browse/SSHD-1004">SSHD-1004</A>
     */
    @Deprecated
    blowfishcbc(Constants.BLOWFISH_CBC, 8, 0, 16, "Blowfish", 128, "Blowfish/CBC/NoPadding", 8),
    /**
     * @deprecated
     * @see        <A HREF="https://issues.apache.org/jira/browse/SSHD-1004">SSHD-1004</A>
     */
    @Deprecated
    tripledescbc(Constants.TRIPLE_DES_CBC, 8, 0, 24, "DESede", 192, "DESede/CBC/NoPadding", 8);

    public static final Set<BuiltinCiphers> VALUES = Collections.unmodifiableSet(EnumSet.allOf(BuiltinCiphers.class));

    private static final Map<String, CipherFactory> EXTENSIONS = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    private final String factoryName;
    private final int ivsize;
    private final int authSize;
    private final int kdfSize;
    private final int keysize;
    private final int blkSize;
    private final String algorithm;
    private final String transformation;
    private final boolean supported;

    BuiltinCiphers(
                   String factoryName, int ivsize, int authSize, int kdfSize,
                   String algorithm, int keySize, String transformation, int blkSize) {
        this.factoryName = factoryName;
        this.ivsize = ivsize;
        this.authSize = authSize;
        this.kdfSize = kdfSize;
        this.keysize = keySize;
        this.algorithm = algorithm;
        this.transformation = transformation;
        this.blkSize = blkSize;
        /*
         * This can be done once since in order to change the support the JVM needs to be stopped, some
         * unlimited-strength files need be installed and then the JVM re-started. Therefore, the answer is not going to
         * change while the JVM is running
         */
        this.supported = Constants.NONE.equals(factoryName) || Cipher.checkSupported(this.transformation, this.keysize);
    }

    @Override
    public final String getName() {
        return factoryName;
    }

    @Override
    public final String toString() {
        return getName();
    }

    /**
     * @return {@code true} if the current JVM configuration supports this cipher - e.g., AES-256 requires the
     *         <A HREF="http://www.oracle.com/technetwork/java/javase/downloads/"> Java Cryptography Extension (JCE)</A>
     */
    @Override
    public boolean isSupported() {
        return supported;
    }

    @Override
    public int getKeySize() {
        return keysize;
    }

    @Override
    public int getIVSize() {
        return ivsize;
    }

    @Override
    public int getAuthenticationTagSize() {
        return authSize;
    }

    @Override
    public int getKdfSize() {
        return kdfSize;
    }

    @Override
    public int getCipherBlockSize() {
        return blkSize;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getTransformation() {
        return transformation;
    }

    @Override
    public Cipher create() {
        return new BaseCipher(
                getIVSize(), getAuthenticationTagSize(), getKdfSize(), getAlgorithm(),
                getKeySize(), getTransformation(), getCipherBlockSize());
    }

    /**
     * Registered a {@link NamedFactory} to be available besides the built-in ones when parsing configuration
     *
     * @param  extension                The factory to register
     * @throws IllegalArgumentException if factory instance is {@code null}, or overrides a built-in one or overrides
     *                                  another registered factory with the same name (case <U>insensitive</U>).
     */
    public static void registerExtension(CipherFactory extension) {
        String name = Objects.requireNonNull(extension, "No extension provided").getName();
        ValidateUtils.checkTrue(fromFactoryName(name) == null, "Extension overrides built-in: %s", name);

        synchronized (EXTENSIONS) {
            ValidateUtils.checkTrue(!EXTENSIONS.containsKey(name), "Extension overrides existing: %s", name);
            EXTENSIONS.put(name, extension);
        }
    }

    /**
     * @return A {@link SortedSet} of the currently registered extensions, sorted according to the factory name (case
     *         <U>insensitive</U>)
     */
    public static NavigableSet<CipherFactory> getRegisteredExtensions() {
        synchronized (EXTENSIONS) {
            return GenericUtils.asSortedSet(NamedResource.BY_NAME_COMPARATOR, EXTENSIONS.values());
        }
    }

    /**
     * Unregisters specified extension
     *
     * @param  name The factory name - ignored if {@code null}/empty
     * @return      The registered extension - {@code null} if not found
     */
    public static NamedFactory<Cipher> unregisterExtension(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }

        synchronized (EXTENSIONS) {
            return EXTENSIONS.remove(name);
        }
    }

    /**
     * @param  s The {@link Enum}'s name - ignored if {@code null}/empty
     * @return   The matching {@link BuiltinCiphers} whose {@link Enum#name()} matches (case <U>insensitive</U>) the
     *           provided argument - {@code null} if no match
     */
    public static BuiltinCiphers fromString(String s) {
        if (GenericUtils.isEmpty(s)) {
            return null;
        }

        for (BuiltinCiphers c : VALUES) {
            if (s.equalsIgnoreCase(c.name())) {
                return c;
            }
        }

        return null;
    }

    /**
     * @param  factory The {@link NamedFactory} for the cipher - ignored if {@code null}
     * @return         The matching {@link BuiltinCiphers} whose factory name matches (case <U>insensitive</U>) the
     *                 cipher factory name
     * @see            #fromFactoryName(String)
     */
    public static BuiltinCiphers fromFactory(NamedFactory<Cipher> factory) {
        if (factory == null) {
            return null;
        } else {
            return fromFactoryName(factory.getName());
        }
    }

    /**
     * @param  name The factory name - ignored if {@code null}/empty
     * @return      The matching {@link BuiltinCiphers} whose factory name matches (case <U>insensitive</U>) the
     *              provided name - {@code null} if no match
     */
    public static BuiltinCiphers fromFactoryName(String name) {
        return NamedResource.findByName(name, String.CASE_INSENSITIVE_ORDER, VALUES);
    }

    /**
     * @param  ciphers A comma-separated list of ciphers' names - ignored if {@code null}/empty
     * @return         A {@link ParseResult} containing the successfully parsed factories and the unknown ones.
     *                 <B>Note:</B> it is up to caller to ensure that the lists do not contain duplicates
     */
    public static ParseResult parseCiphersList(String ciphers) {
        return parseCiphersList(GenericUtils.split(ciphers, ','));
    }

    public static ParseResult parseCiphersList(String... ciphers) {
        return parseCiphersList(GenericUtils.isEmpty((Object[]) ciphers) ? Collections.emptyList() : Arrays.asList(ciphers));
    }

    public static ParseResult parseCiphersList(Collection<String> ciphers) {
        if (GenericUtils.isEmpty(ciphers)) {
            return ParseResult.EMPTY;
        }

        List<CipherFactory> factories = new ArrayList<>(ciphers.size());
        List<String> unknown = Collections.emptyList();
        for (String name : ciphers) {
            CipherFactory c = resolveFactory(name);
            if (c != null) {
                factories.add(c);
            } else {
                // replace the (unmodifiable) empty list with a real one
                if (unknown.isEmpty()) {
                    unknown = new ArrayList<>();
                }
                unknown.add(name);
            }
        }

        return new ParseResult(factories, unknown);
    }

    /**
     * @param  name The factory name
     * @return      The factory or {@code null} if it is neither a built-in one or a registered extension
     */
    public static CipherFactory resolveFactory(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }

        CipherFactory c = fromFactoryName(name);
        if (c != null) {
            return c;
        }

        synchronized (EXTENSIONS) {
            return EXTENSIONS.get(name);
        }
    }

    /**
     * Holds the result of {@link BuiltinCiphers#parseCiphersList(String)}
     *
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    public static class ParseResult extends NamedFactoriesListParseResult<Cipher, CipherFactory> {
        public static final ParseResult EMPTY = new ParseResult(Collections.emptyList(), Collections.emptyList());

        public ParseResult(List<CipherFactory> parsed, List<String> unsupported) {
            super(parsed, unsupported);
        }
    }

    public static final class Constants {
        public static final String NONE = "none";
        public static final Pattern NONE_CIPHER_PATTERN = Pattern.compile("(^|.*,)" + NONE + "($|,.*)");

        public static final String AES128_CBC = "aes128-cbc";
        public static final String AES128_CTR = "aes128-ctr";
        public static final String AES128_GCM = "aes128-gcm@openssh.com";
        public static final String AES192_CBC = "aes192-cbc";
        public static final String AES192_CTR = "aes192-ctr";
        public static final String AES256_CBC = "aes256-cbc";
        public static final String AES256_CTR = "aes256-ctr";
        public static final String AES256_GCM = "aes256-gcm@openssh.com";
        public static final String ARCFOUR128 = "arcfour128";
        public static final String ARCFOUR256 = "arcfour256";
        public static final String BLOWFISH_CBC = "blowfish-cbc";
        public static final String TRIPLE_DES_CBC = "3des-cbc";

        private Constants() {
            throw new UnsupportedOperationException("No instance allowed");
        }

        /**
         * @param  s A comma-separated list of ciphers - ignored if {@code null}/empty
         * @return   {@code true} if the {@link #NONE} cipher name appears in it
         */
        public static boolean isNoneCipherIncluded(String s) {
            if (GenericUtils.isEmpty(s)) {
                return false;
            }
            Matcher m = NONE_CIPHER_PATTERN.matcher(s);
            return m.matches();
        }

    }
}
