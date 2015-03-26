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

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.Cipher;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.util.GenericUtils;

/**
 * Provides easy access to the currently implemented ciphers
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum BuiltinCiphers implements NamedFactory<Cipher> {
    none(Constants.NONE) {
        @Override
        public Cipher create() {
            return new CipherNone();
        }
    },
    aes128cbc(Constants.AES128_CBC) {
        @Override
        public Cipher create() {
            return new BaseCipher(16, 16, "AES", "AES/CBC/NoPadding");
        }
    },
    aes128ctr(Constants.AES128_CTR) {
        @Override
        public Cipher create() {
            return new BaseCipher(16, 16, "AES", "AES/CTR/NoPadding");
        }
    },
    aes192cbc(Constants.AES192_CBC) {
        @Override
        public Cipher create() {
            return new BaseCipher(16, 24, "AES", "AES/CBC/NoPadding");
        }
    },
    aes192ctr(Constants.AES192_CTR) {
        @Override
        public Cipher create() {
            return new BaseCipher(16, 24, "AES", "AES/CTR/NoPadding");
        }
    },
    aes256cbc(Constants.AES256_CBC) {
        @Override
        public Cipher create() {
            return new BaseCipher(16, 32, "AES", "AES/CBC/NoPadding");
        }
    },
    aes256ctr(Constants.AES256_CTR) {
        @Override
        public Cipher create() {
            return new BaseCipher(16, 32, "AES", "AES/CTR/NoPadding");
        }
    },
    arcfour128(Constants.ARCFOUR128) {
        @Override
        public Cipher create() {
            return new BaseRC4Cipher(8, 16);
        }
    },
    arcfour256(Constants.ARCFOUR256) {
        @Override
        public Cipher create() {
            return new BaseRC4Cipher(8, 32);
        }
    },
    blowfishcbc(Constants.BLOWFISH_CBC) {
        @Override
        public Cipher create() {
            return new BaseCipher(8, 16, "Blowfish", "Blowfish/CBC/NoPadding");
        }
    },
    tripledescbc(Constants.DES_CBC) {
        @Override
        public Cipher create() {
            return new BaseCipher(8, 24, "DESede", "DESede/CBC/NoPadding");
        }
    };

    private final String factoryName;

    @Override
    public final String getName() {
        return factoryName;
    }

    BuiltinCiphers(String facName) {
        factoryName = facName;
    }

    private final AtomicReference<Boolean> _supported = new AtomicReference<>(null);

    /**
     * @return {@code true} if the current JVM configuration supports this
     * cipher - e.g., AES-256 requires the <A HREF="http://www.oracle.com/technetwork/java/javase/downloads/">
     * Java Cryptography Extension (JCE)</A>
     */
    public boolean isSupported() {
        Boolean value;
        synchronized (_supported) {
            if ((value = _supported.get()) == null) {
                // see BaseBuilder#fillWithDefaultValues
                try {
                    Exception t = CipherUtils.checkSupported(create());
                    value = t == null;
                } catch (Exception e) {
                    value = Boolean.FALSE;
                }

                _supported.set(value);
            }
        }

        return value;
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

    private static class Constants {
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
        public static final String DES_CBC = "3des-cbc";
    }
}
