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
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.keyprovider.KeyTypeIndicator;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum BuiltinIdentities implements Identity {
    RSA(Constants.RSA, RSAPublicKey.class, RSAPrivateKey.class, KeyPairProvider.SSH_RSA),
    DSA(Constants.DSA, DSAPublicKey.class, DSAPrivateKey.class, KeyPairProvider.SSH_DSS),
    ECDSA(Constants.ECDSA, KeyUtils.EC_ALGORITHM, ECPublicKey.class, ECPrivateKey.class,
          ECCurves.VALUES.stream().map(KeyTypeIndicator::getKeyType).collect(Collectors.toList())) {
        @Override
        public boolean isSupported() {
            return SecurityUtils.isECCSupported();
        }
    },
    ED25119(Constants.ED25519, SecurityUtils.EDDSA,
            SecurityUtils.getEDDSAPublicKeyType(),
            SecurityUtils.getEDDSAPrivateKeyType(),
            KeyPairProvider.SSH_ED25519) {
        @Override
        public boolean isSupported() {
            return SecurityUtils.isEDDSACurveSupported();
        }
    };

    public static final Set<BuiltinIdentities> VALUES = Collections.unmodifiableSet(EnumSet.allOf(BuiltinIdentities.class));

    /**
     * A case <u>insensitive</u> {@link NavigableSet} of all built-in identities names
     */
    public static final NavigableSet<String> NAMES = Collections.unmodifiableNavigableSet(
            GenericUtils.asSortedSet(
                    String.CASE_INSENSITIVE_ORDER, NamedResource.getNameList(VALUES)));

    private final String name;
    private final String algorithm;
    private final Class<? extends PublicKey> pubType;
    private final Class<? extends PrivateKey> prvType;
    private final NavigableSet<String> types;

    BuiltinIdentities(String type, Class<? extends PublicKey> pubType, Class<? extends PrivateKey> prvType, String keyType) {
        this(type, type, pubType, prvType, keyType);
    }

    BuiltinIdentities(String name, String algorithm,
                      Class<? extends PublicKey> pubType,
                      Class<? extends PrivateKey> prvType,
                      String keyType) {
        this(name, algorithm, pubType, prvType,
             Collections.singletonList(
                     ValidateUtils.checkNotNullAndNotEmpty(keyType, "No key type specified")));
    }

    BuiltinIdentities(String name, String algorithm,
                      Class<? extends PublicKey> pubType,
                      Class<? extends PrivateKey> prvType,
                      Collection<String> keyTypes) {
        this.name = name.toLowerCase();
        this.algorithm = algorithm.toUpperCase();
        this.pubType = pubType;
        this.prvType = prvType;
        this.types = Collections.unmodifiableNavigableSet(
                GenericUtils.asSortedSet(String.CASE_INSENSITIVE_ORDER,
                        ValidateUtils.checkNotNullAndNotEmpty(keyTypes, "No key type names provided")));
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
    public NavigableSet<String> getSupportedKeyTypes() {
        return types;
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
     * @param  name The identity name - ignored if {@code null}/empty
     * @return      The matching {@link BuiltinIdentities} whose {@link #getName()} value matches case
     *              <U>insensitive</U> or {@code null} if no match found
     */
    public static BuiltinIdentities fromName(String name) {
        return NamedResource.findByName(name, String.CASE_INSENSITIVE_ORDER, VALUES);
    }

    /**
     * @param  algorithm The algorithm - ignored if {@code null}/empty
     * @return           The matching {@link BuiltinIdentities} whose {@link #getAlgorithm()} value matches case
     *                   <U>insensitive</U> or {@code null} if no match found
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
     * @param  kp The {@link KeyPair} - ignored if {@code null}
     * @return    The matching {@link BuiltinIdentities} provided <U>both</U> public and public keys are of the same
     *            type - {@code null} if no match could be found
     * @see       #fromKey(Key)
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
            return null; // some kind of mixed keys...
        }
    }

    /**
     * @param  key The {@link Key} instance - ignored if {@code null}
     * @return     The matching {@link BuiltinIdentities} whose either public or private key type matches the requested
     *             one or {@code null} if no match found
     * @see        #fromKeyType(Class)
     */
    public static BuiltinIdentities fromKey(Key key) {
        return fromKeyType((key == null) ? null : key.getClass());
    }

    /**
     * @param  clazz The key type - ignored if {@code null} or not a {@link Key} class
     * @return       The matching {@link BuiltinIdentities} whose either public or private key type matches the
     *               requested one or {@code null} if no match found
     * @see          #getPublicKeyType()
     * @see          #getPrivateKeyType()
     */
    public static BuiltinIdentities fromKeyType(Class<?> clazz) {
        if ((clazz == null) || (!Key.class.isAssignableFrom(clazz))) {
            return null;
        }

        for (BuiltinIdentities id : VALUES) {
            Class<?> pubType = id.getPublicKeyType();
            Class<?> prvType = id.getPrivateKeyType();
            // Ignore placeholder classes (e.g., if ed25519 is not supported)
            if ((prvType == null) || (pubType == null)) {
                continue;
            }
            if ((prvType == PrivateKey.class) || (pubType == PublicKey.class)) {
                continue;
            }
            if (pubType.isAssignableFrom(clazz) || prvType.isAssignableFrom(clazz)) {
                return id;
            }
        }

        return null;
    }

    /**
     * @param  typeName The {@code OpenSSH} key type e.g., {@code ssh-rsa, ssh-dss, ecdsa-sha2-nistp384}. Ignored if
     *                  {@code null}/empty.
     * @return          The {@link BuiltinIdentities} that reported the type name as its {@link #getSupportedKeyTypes()}
     *                  (case <U>insensitive</U>) - {@code null} if no match found
     * @see             KeyTypeNamesSupport#findSupporterByKeyTypeName(String, Collection)
     */
    public static BuiltinIdentities fromKeyTypeName(String typeName) {
        return KeyTypeNamesSupport.findSupporterByKeyTypeName(typeName, VALUES);
    }

    /**
     * Contains the names of the identities
     */
    public static final class Constants {
        public static final String RSA = KeyUtils.RSA_ALGORITHM;
        public static final String DSA = KeyUtils.DSS_ALGORITHM;
        public static final String ECDSA = "ECDSA";
        public static final String ED25519 = "ED25519";

        private Constants() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }
}
