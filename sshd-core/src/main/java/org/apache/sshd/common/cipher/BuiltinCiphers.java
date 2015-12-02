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
    none(Constants.NONE, 0, 0, "None", "None") {
        @Override
        public Cipher create() {
            return new CipherNone();
        }
    },
    aes128cbc(Constants.AES128_CBC, 16, 16, "AES", "AES/CBC/NoPadding"),
    aes128ctr(Constants.AES128_CTR, 16, 16, "AES", "AES/CTR/NoPadding"),
    aes192cbc(Constants.AES192_CBC, 16, 24, "AES", "AES/CBC/NoPadding"),
    aes192ctr(Constants.AES192_CTR, 16, 24, "AES", "AES/CTR/NoPadding"),
    aes256cbc(Constants.AES256_CBC, 16, 32, "AES", "AES/CBC/NoPadding"),
    aes256ctr(Constants.AES256_CTR, 16, 32, "AES", "AES/CTR/NoPadding"),
    arcfour128(Constants.ARCFOUR128, 8, 16, "ARCFOUR", "RC4") {
        @Override
        public Cipher create() {
            return new BaseRC4Cipher(getIVSize(), getBlockSize());
        }
    },
    arcfour256(Constants.ARCFOUR256, 8, 32, "ARCFOUR", "RC4") {
        @Override
        public Cipher create() {
            return new BaseRC4Cipher(getIVSize(), getBlockSize());
        }
    },
    blowfishcbc(Constants.BLOWFISH_CBC, 8, 16, "Blowfish", "Blowfish/CBC/NoPadding"),
    tripledescbc(Constants.TRIPLE_DES_CBC, 8, 24, "DESede", "DESede/CBC/NoPadding");

    public static final Set<BuiltinCiphers> VALUES =
            Collections.unmodifiableSet(EnumSet.allOf(BuiltinCiphers.class));

    private static final Map<String, CipherFactory> EXTENSIONS =
            new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    private final String factoryName;
    private final int ivsize;
    private final int blocksize;
    private final int keysize;
    private final String algorithm;
    private final String transformation;
    private final boolean supported;

    BuiltinCiphers(String factoryName, int ivsize, int blocksize, String algorithm, String transformation) {
        this.factoryName = factoryName;
        this.ivsize = ivsize;
        this.blocksize = blocksize;
        this.keysize = blocksize * Byte.SIZE;
        this.algorithm = algorithm;
        this.transformation = transformation;
        /*
         * This can be done once since in order to change the support the JVM
         * needs to be stopped, some unlimited-strength files need be installed
         * and then the JVM re-started. Therefore, the answer is not going to
         * change while the JVM is running
         */
        this.supported = Constants.NONE.equals(factoryName) || Cipher.Utils.checkSupported(this.transformation, this.keysize);
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
     * @return {@code true} if the current JVM configuration supports this
     * cipher - e.g., AES-256 requires the <A HREF="http://www.oracle.com/technetwork/java/javase/downloads/">
     * Java Cryptography Extension (JCE)</A>
     */
    @Override
    public boolean isSupported() {
        return supported;
    }

    /**
     * @return The key size (in bits) for the cipher
     */
    public int getKeySize() {
        return keysize;
    }

    @Override
    public int getIVSize() {
        return ivsize;
    }

    @Override
    public int getBlockSize() {
        return blocksize;
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
        return new BaseCipher(getIVSize(), getBlockSize(), getAlgorithm(), getTransformation());
    }

    /**
     * Registered a {@link NamedFactory} to be available besides the built-in
     * ones when parsing configuration
     *
     * @param extension The factory to register
     * @throws IllegalArgumentException if factory instance is {@code null},
     *                                  or overrides a built-in one or overrides another registered factory
     *                                  with the same name (case <U>insensitive</U>).
     */
    public static void registerExtension(CipherFactory extension) {
        String name = ValidateUtils.checkNotNull(extension, "No extension provided").getName();
        ValidateUtils.checkTrue(fromFactoryName(name) == null, "Extension overrides built-in: %s", name);

        synchronized (EXTENSIONS) {
            ValidateUtils.checkTrue(!EXTENSIONS.containsKey(name), "Extension overrides existing: %s", name);
            EXTENSIONS.put(name, extension);
        }
    }

    /**
     * @return A {@link SortedSet} of the currently registered extensions, sorted
     * according to the factory name (case <U>insensitive</U>)
     */
    public static SortedSet<CipherFactory> getRegisteredExtensions() {
        // TODO for JDK-8 return Collections.emptySortedSet()
        synchronized (EXTENSIONS) {
            return GenericUtils.asSortedSet(NamedResource.BY_NAME_COMPARATOR, EXTENSIONS.values());
        }
    }

    /**
     * Unregisters specified extension
     *
     * @param name The factory name - ignored if {@code null}/empty
     * @return The registered extension - {@code null} if not found
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
     * @param s The {@link Enum}'s name - ignored if {@code null}/empty
     * @return The matching {@link BuiltinCiphers} whose {@link Enum#name()} matches
     * (case <U>insensitive</U>) the provided argument - {@code null} if no match
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
     * @param factory The {@link NamedFactory} for the cipher - ignored if {@code null}
     * @return The matching {@link BuiltinCiphers} whose factory name matches
     * (case <U>insensitive</U>) the cipher factory name
     * @see #fromFactoryName(String)
     */
    public static BuiltinCiphers fromFactory(NamedFactory<Cipher> factory) {
        if (factory == null) {
            return null;
        } else {
            return fromFactoryName(factory.getName());
        }
    }

    /**
     * @param name The factory name - ignored if {@code null}/empty
     * @return The matching {@link BuiltinCiphers} whose factory name matches
     * (case <U>insensitive</U>) the provided name - {@code null} if no match
     */
    public static BuiltinCiphers fromFactoryName(String name) {
        return NamedResource.Utils.findByName(name, String.CASE_INSENSITIVE_ORDER, VALUES);
    }

    /**
     * @param ciphers A comma-separated list of ciphers' names - ignored
     *                if {@code null}/empty
     * @return A {@link ParseResult} containing the successfully parsed
     * factories and the unknown ones. <B>Note:</B> it is up to caller to
     * ensure that the lists do not contain duplicates
     */
    public static ParseResult parseCiphersList(String ciphers) {
        return parseCiphersList(GenericUtils.split(ciphers, ','));
    }

    public static ParseResult parseCiphersList(String... ciphers) {
        return parseCiphersList(GenericUtils.isEmpty((Object[]) ciphers) ? Collections.<String>emptyList() : Arrays.asList(ciphers));
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
     * @param name The factory name
     * @return The factory or {@code null} if it is neither a built-in one
     * or a registered extension
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
        public static final ParseResult EMPTY = new ParseResult(Collections.<CipherFactory>emptyList(), Collections.<String>emptyList());

        public ParseResult(List<CipherFactory> parsed, List<String> unsupported) {
            super(parsed, unsupported);
        }
    }

    public static class Constants {
        public static final String NONE = "none";
        public static final Pattern NONE_CIPHER_PATTERN =
                Pattern.compile("(^|.*,)" + NONE + "($|,.*)");

        public static final String AES128_CBC = "aes128-cbc";
        public static final String AES128_CTR = "aes128-ctr";
        public static final String AES192_CBC = "aes192-cbc";
        public static final String AES192_CTR = "aes192-ctr";
        public static final String AES256_CBC = "aes256-cbc";
        public static final String AES256_CTR = "aes256-ctr";
        public static final String ARCFOUR128 = "arcfour128";
        public static final String ARCFOUR256 = "arcfour256";
        public static final String BLOWFISH_CBC = "blowfish-cbc";
        public static final String TRIPLE_DES_CBC = "3des-cbc";

        /**
         * @param s A comma-separated list of ciphers - ignored if {@code null}/empty
         * @return {@code true} if the {@link #NONE} cipher name appears in it
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
