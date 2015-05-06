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

package org.apache.sshd.common.cipher;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import org.apache.sshd.common.Cipher;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.OptionalFeature;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Provides easy access to the currently implemented ciphers
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum BuiltinCiphers implements NamedFactory<Cipher>, OptionalFeature {
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

    private final String factoryName;
    private final int ivsize;
    private final int blocksize;
    private final String algorithm;
    private final String transformation;

    @Override
    public final String getName() {
        return factoryName;
    }

    @Override
    public final String toString() {
        return getName();
    }

    BuiltinCiphers(String factoryName, int ivsize, int blocksize, String algorithm, String transformation) {
        this.factoryName = factoryName;
        this.ivsize = ivsize;
        this.blocksize = blocksize;
        this.algorithm = algorithm;
        this.transformation = transformation;

    }

    /**
     * @return {@code true} if the current JVM configuration supports this
     * cipher - e.g., AES-256 requires the <A HREF="http://www.oracle.com/technetwork/java/javase/downloads/">
     * Java Cryptography Extension (JCE)</A>
     */
    @Override
    public boolean isSupported() {
        try {
            int maxKeyLength = javax.crypto.Cipher.getMaxAllowedKeyLength(getAlgorithm());
            return maxKeyLength >= (1l << getBlockSize());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Retrieves the size of the initialization vector
     *
     * @return
     */
    public int getIVSize() {
        return ivsize;
    }

    /**
     * Retrieves the block size for this cipher
     *
     * @return
     */
    public int getBlockSize() {
        return blocksize;
    }

    /**
     * Retrieves the algorithm for this cipher
     *
     * @return
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Retrieves the algorithm for this cipher
     *
     * @return
     */
    public String getTransformation() {
        return transformation;
    }

    @Override
    public Cipher create() {
        return new BaseCipher(getIVSize(), getBlockSize(), getAlgorithm(), getTransformation());
    }

    public static final Set<BuiltinCiphers> VALUES =
            Collections.unmodifiableSet(EnumSet.allOf(BuiltinCiphers.class));

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
     * @param n The factory name - ignored if {@code null}/empty
     * @return The matching {@link BuiltinCiphers} whose factory name matches
     * (case <U>insensitive</U>) the provided name - {@code null} if no match
     */
    public static BuiltinCiphers fromFactoryName(String n) {
        if (GenericUtils.isEmpty(n)) {
            return null;
        }

        for (BuiltinCiphers c : VALUES) {
            if (n.equalsIgnoreCase(c.getName())) {
                return c;
            }
        }

        return null;
    }

    /**
     * @param ciphers A comma-separated list of ciphers' names - ignored
     * if {@code null}/empty
     * @return A {@link List} of all the {@link NamedFactory}-ies whose
     * name appears in the string and represent a built-in cipher. Any
     * unknown name is <U>ignored</U>. The order of the returned result
     * is the same as the original order - bar the unknown ciphers.
     * <B>Note:</B> it is up to caller to ensure that the list does not
     * contain duplicates
     */
    public static final List<NamedFactory<Cipher>> parseCiphersList(String ciphers) {
        return parseCiphersList(GenericUtils.split(ciphers, ','));
    }

    public static final List<NamedFactory<Cipher>> parseCiphersList(String ... ciphers) {
        return parseCiphersList(GenericUtils.isEmpty((Object[]) ciphers) ? Collections.<String>emptyList() : Arrays.asList(ciphers));
    }

    public static final List<NamedFactory<Cipher>> parseCiphersList(Collection<String> ciphers) {
        if (GenericUtils.isEmpty(ciphers)) {
            return Collections.emptyList();
        }
        
        List<NamedFactory<Cipher>>    result=new ArrayList<NamedFactory<Cipher>>(ciphers.size());
        for (String name : ciphers) {
            BuiltinCiphers  c=ValidateUtils.checkNotNull(fromFactoryName(name), "Bad factory name (%s) in %s", name, ciphers);
            result.add(c);
        }
        
        return result;
    }

    public static final class Constants {
        public static final String NONE = "none";
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
    }
}
