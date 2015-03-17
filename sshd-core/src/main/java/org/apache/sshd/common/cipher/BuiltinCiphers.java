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
public enum BuiltinCiphers implements NamedFactory<NamedFactory<Cipher>> {
    none(CipherNone.Factory.NAME, CipherNone.class) {
        @Override
        public NamedFactory<Cipher> create() {
            return new CipherNone.Factory();
        }
    },
    aes128cbc(AES128CBC.Factory.NAME, AES128CBC.class) {
        @Override
        public NamedFactory<Cipher> create() {
            return new AES128CBC.Factory();
        }
    },
    aes128ctr(AES128CTR.Factory.NAME, AES128CTR.class) {
        @Override
        public NamedFactory<Cipher> create() {
            return new AES128CTR.Factory();
        }
    },
    aes192cbc(AES192CBC.Factory.NAME, AES192CBC.class) {
        @Override
        public NamedFactory<Cipher> create() {
            return new AES192CBC.Factory();
        }
    },
    aes192ctr(AES192CTR.Factory.NAME, AES192CTR.class) {
        @Override
        public NamedFactory<Cipher> create() {
            return new AES192CTR.Factory();
        }
    },
    aes256cbc(AES256CBC.Factory.NAME, AES256CBC.class) {
        @Override
        public NamedFactory<Cipher> create() {
            return new AES256CBC.Factory();
        }
    },
    aes256ctr(AES256CTR.Factory.NAME, AES256CTR.class) {
        @Override
        public NamedFactory<Cipher> create() {
            return new AES256CTR.Factory();
        }
    },
    arcfour128(ARCFOUR128.Factory.NAME, ARCFOUR128.class) {
        @Override
        public NamedFactory<Cipher> create() {
            return new ARCFOUR128.Factory();
        }
    },
    arcfour256(ARCFOUR256.Factory.NAME, ARCFOUR256.class) {
        @Override
        public NamedFactory<Cipher> create() {
            return new ARCFOUR256.Factory();
        }
    },
    blowfishcbc(BlowfishCBC.Factory.NAME, BlowfishCBC.class) {
        @Override
        public NamedFactory<Cipher> create() {
            return new BlowfishCBC.Factory();
        }
    },
    tripledescbc(TripleDESCBC.Factory.NAME, TripleDESCBC.class) {
        @Override
        public NamedFactory<Cipher> create() {
            return new TripleDESCBC.Factory();
        }
    };

    private final String factoryName;
    private Class<? extends Cipher> cipherType;

    @Override
    public final String getName() {
        return factoryName;
    }

    public final Class<? extends Cipher> getCipherType() {
        return cipherType;
    }

    BuiltinCiphers(String facName, Class<? extends Cipher> cipherClass) {
        factoryName = facName;
        cipherType = cipherClass;
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

    /**
     * @param c The {@link Cipher} instance - ignored if {@code null}
     * @return The matching {@link BuiltinCiphers} - {@code null} if no match
     * @see #fromCipherType(Class)
     */
    public static BuiltinCiphers fromCipher(Cipher c) {
        if (c == null) {
            return null;
        } else {
            return fromCipherType(c.getClass());
        }
    }

    /**
     * @param type The cipher type - ignored if {@code null} or not a
     *             {@link Cipher} derived class
     * @return The matching {@link BuiltinCiphers} - {@code null} if no match
     */
    public static BuiltinCiphers fromCipherType(Class<?> type) {
        if ((type == null) || (!Cipher.class.isAssignableFrom(type))) {
            return null;
        }

        for (BuiltinCiphers c : VALUES) {
            Class<?> t = c.getCipherType();
            if (t.isAssignableFrom(type)) {
                return c;
            }
        }

        return null;
    }
}
