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

package org.apache.sshd.common.config.keys;

import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum BuiltinIdentities implements Identity {
    RSA(Constants.RSA, RSAPublicKey.class, RSAPrivateKey.class),
    DSA(Constants.DSA, DSAPublicKey.class, DSAPrivateKey.class),
    ECDSA(Constants.ECDSA, KeyUtils.EC_ALGORITHM, ECPublicKey.class, ECPrivateKey.class) {
        @Override
        public boolean isSupported() {
            return SecurityUtils.hasEcc();
        }
    };

    public static final Set<BuiltinIdentities> VALUES =
            Collections.unmodifiableSet(EnumSet.allOf(BuiltinIdentities.class));

    public static final Set<String> NAMES =
            Collections.unmodifiableSet(new TreeSet<String>(String.CASE_INSENSITIVE_ORDER) {
                private static final long serialVersionUID = 1L;    // we're not serializing it

                {
                    addAll(NamedResource.Utils.getNameList(VALUES));
                }
            });

    private final String name;
    private final String algorithm;
    private final Class<? extends PublicKey> pubType;
    private final Class<? extends PrivateKey> prvType;

    BuiltinIdentities(String type, Class<? extends PublicKey> pubType, Class<? extends PrivateKey> prvType) {
        this(type, type, pubType, prvType);
    }

    BuiltinIdentities(String name, String algorithm, Class<? extends PublicKey> pubType, Class<? extends PrivateKey> prvType) {
        this.name = name.toLowerCase();
        this.algorithm = algorithm.toUpperCase();
        this.pubType = pubType;
        this.prvType = prvType;
    }

    @Override
    public final String getName() {
        return name;
    }

    @Override
    public boolean isSupported() {
        return true;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public final Class<? extends PublicKey> getPublicKeyType() {
        return pubType;
    }

    @Override
    public final Class<? extends PrivateKey> getPrivateKeyType() {
        return prvType;
    }

    /**
     * @param name The identity name - ignored if {@code null}/empty
     * @return The matching {@link BuiltinIdentities} whose {@link #getName()}
     * value matches case <U>insensitive</U> or {@code null} if no match found
     */
    public static BuiltinIdentities fromName(String name) {
        return NamedResource.Utils.findByName(name, String.CASE_INSENSITIVE_ORDER, VALUES);
    }

    /**
     * @param algorithm The algorithm  - ignored if {@code null}/empty
     * @return The matching {@link BuiltinIdentities} whose {@link #getAlgorithm()}
     * value matches case <U>insensitive</U> or {@code null} if no match found
     */
    public static BuiltinIdentities fromAlgorithm(String algorithm) {
        if (GenericUtils.isEmpty(algorithm)) {
            return null;
        }

        for (BuiltinIdentities id : VALUES) {
            if (algorithm.equalsIgnoreCase(id.getAlgorithm())) {
                return id;
            }
        }

        return null;
    }

    /**
     * @param kp The {@link KeyPair} - ignored if {@code null}
     * @return The matching {@link BuiltinIdentities} provided <U>both</U>
     * public and public keys are of the same type - {@code null} if no
     * match could be found
     * @see #fromKey(Key)
     */
    public static BuiltinIdentities fromKeyPair(KeyPair kp) {
        if (kp == null) {
            return null;
        }

        BuiltinIdentities i1 = fromKey(kp.getPublic());
        BuiltinIdentities i2 = fromKey(kp.getPrivate());
        if (Objects.equals(i1, i2)) {
            return i1;
        } else {
            return null;    // some kind of mixed keys...
        }
    }

    /**
     * @param key The {@link Key} instance - ignored if {@code null}
     * @return The matching {@link BuiltinIdentities} whose either public or
     * private key type matches the requested one or {@code null} if no match found
     * @see #fromKeyType(Class)
     */
    public static BuiltinIdentities fromKey(Key key) {
        return fromKeyType((key == null) ? null : key.getClass());
    }

    /**
     * @param clazz The key type - ignored if {@code null} or not
     *              a {@link Key} class
     * @return The matching {@link BuiltinIdentities} whose either public or
     * private key type matches the requested one or {@code null} if no match found
     * @see #getPublicKeyType()
     * @see #getPrivateKeyType()
     */
    public static BuiltinIdentities fromKeyType(Class<?> clazz) {
        if ((clazz == null) || (!Key.class.isAssignableFrom(clazz))) {
            return null;
        }

        for (BuiltinIdentities id : VALUES) {
            Class<?> pubType = id.getPublicKeyType();
            Class<?> prvType = id.getPrivateKeyType();
            if (pubType.isAssignableFrom(clazz) || prvType.isAssignableFrom(clazz)) {
                return id;
            }
        }

        return null;
    }

    /**
     * Contains the names of the identities
     */
    public static final class Constants {
        public static final String RSA = KeyUtils.RSA_ALGORITHM;
        public static final String DSA = KeyUtils.DSS_ALGORITHM;
        public static final String ECDSA = "ECDSA";
    }
}
