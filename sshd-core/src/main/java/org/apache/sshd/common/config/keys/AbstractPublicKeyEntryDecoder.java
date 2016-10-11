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

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.util.Collection;
import java.util.Objects;

import org.apache.sshd.common.util.ValidateUtils;

/**
 * Useful base class implementation for a decoder of an {@code OpenSSH} encoded key data
 *
 * @param <PUB> Type of {@link PublicKey}
 * @param <PRV> Type of {@link PrivateKey}
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractPublicKeyEntryDecoder<PUB extends PublicKey, PRV extends PrivateKey>
        implements PublicKeyEntryDecoder<PUB, PRV> {
    private final Class<PUB> pubType;
    private final Class<PRV> prvType;
    private final Collection<String> names;

    protected AbstractPublicKeyEntryDecoder(Class<PUB> pubType, Class<PRV> prvType, Collection<String> names) {
        this.pubType = Objects.requireNonNull(pubType, "No public key type specified");
        this.prvType = Objects.requireNonNull(prvType, "No private key type specified");
        this.names = ValidateUtils.checkNotNullAndNotEmpty(names, "No type names provided");
    }

    @Override
    public final Class<PUB> getPublicKeyType() {
        return pubType;
    }

    @Override
    public final Class<PRV> getPrivateKeyType() {
        return prvType;
    }

    @Override
    public KeyPair cloneKeyPair(KeyPair kp) throws GeneralSecurityException {
        if (kp == null) {
            return null;
        }

        PUB pubCloned = null;
        PublicKey pubOriginal = kp.getPublic();
        Class<PUB> pubExpected = getPublicKeyType();
        if (pubOriginal != null) {
            Class<?> orgType = pubOriginal.getClass();
            if (!pubExpected.isAssignableFrom(orgType)) {
                throw new InvalidKeyException("Mismatched public key types: expected=" + pubExpected.getSimpleName() + ", actual=" + orgType.getSimpleName());
            }

            pubCloned = clonePublicKey(pubExpected.cast(pubOriginal));
        }

        PRV prvCloned = null;
        PrivateKey prvOriginal = kp.getPrivate();
        Class<PRV> prvExpected = getPrivateKeyType();
        if (prvOriginal != null) {
            Class<?> orgType = prvOriginal.getClass();
            if (!prvExpected.isAssignableFrom(orgType)) {
                throw new InvalidKeyException("Mismatched private key types: expected=" + prvExpected.getSimpleName() + ", actual=" + orgType.getSimpleName());
            }

            prvCloned = clonePrivateKey(prvExpected.cast(prvOriginal));
        }

        return new KeyPair(pubCloned, prvCloned);
    }

    @Override
    public Collection<String> getSupportedTypeNames() {
        return names;
    }

    public PUB generatePublicKey(KeySpec keySpec) throws GeneralSecurityException {
        KeyFactory factory = getKeyFactoryInstance();
        Class<PUB> keyType = getPublicKeyType();
        return keyType.cast(factory.generatePublic(keySpec));
    }

    public PRV generatePrivateKey(KeySpec keySpec) throws GeneralSecurityException {
        KeyFactory factory = getKeyFactoryInstance();
        Class<PRV> keyType = getPrivateKeyType();
        return keyType.cast(factory.generatePrivate(keySpec));
    }

    @Override
    public KeyPair generateKeyPair(int keySize) throws GeneralSecurityException {
        KeyPairGenerator gen = getKeyPairGenerator();
        gen.initialize(keySize);
        return gen.generateKeyPair();
    }

    @Override
    public String toString() {
        return getPublicKeyType().getSimpleName() + ": " + getSupportedTypeNames();
    }
}
