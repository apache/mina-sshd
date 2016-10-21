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

package org.apache.sshd.common.util.security.eddsa;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Objects;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyEntryResolver;
import org.apache.sshd.common.config.keys.impl.AbstractPrivateKeyEntryDecoder;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class OpenSSHEd25519PrivateKeyEntryDecoder extends AbstractPrivateKeyEntryDecoder<EdDSAPublicKey, EdDSAPrivateKey> {
    public static final OpenSSHEd25519PrivateKeyEntryDecoder INSTANCE = new OpenSSHEd25519PrivateKeyEntryDecoder();

    public OpenSSHEd25519PrivateKeyEntryDecoder() {
        super(EdDSAPublicKey.class, EdDSAPrivateKey.class, Collections.unmodifiableList(Collections.singletonList(KeyPairProvider.SSH_ED25519)));
    }

    @Override
    public EdDSAPrivateKey decodePrivateKey(String keyType, FilePasswordProvider passwordProvider, InputStream keyData)
            throws IOException, GeneralSecurityException {
        if (!KeyPairProvider.SSH_ED25519.equals(keyType)) {
            throw new InvalidKeyException("Unsupported key type: " + keyType);
        }

        if (!SecurityUtils.isEDDSACurveSupported()) {
            throw new NoSuchAlgorithmException(SecurityUtils.EDDSA + " provider not supported");
        }

        byte[] seed = KeyEntryResolver.readRLEBytes(keyData);   // a.k.a pk in OpenSSH C code
        byte[] signature = KeyEntryResolver.readRLEBytes(keyData);   // a.k.a sk in OpenSSH C code
        if (signature.length != seed.length * 2) {
            throw new InvalidKeyException("Mismatched signature (" + signature.length + ") vs. seed (" + seed.length + ") length");
        }

        EdDSAParameterSpec params = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512);
        EdDSAPrivateKeySpec keySpec = new EdDSAPrivateKeySpec(seed, params);
        return generatePrivateKey(keySpec);
    }

    @Override
    public String encodePrivateKey(OutputStream s, EdDSAPrivateKey key) throws IOException {
        Objects.requireNonNull(key, "No private key provided");

        //  how
        byte[] seed = key.getSeed();
        Objects.requireNonNull(seed, "No ssed");
        /* TODO see https://svn.nmap.org/ncrack/opensshlib/ed25519.c
        byte[] signature = signEd25519KeyPair(seed);
        KeyEntryResolver.writeRLEBytes(s, seed);
        KeyEntryResolver.writeRLEBytes(s, signature);
        return KeyPairProvider.SSH_ED25519;
        */
        return null;
    }

    @Override
    public boolean isPublicKeyRecoverySupported() {
        return true;
    }

    @Override
    public EdDSAPublicKey recoverPublicKey(EdDSAPrivateKey prvKey) throws GeneralSecurityException {
        if (!SecurityUtils.isEDDSACurveSupported()) {
            throw new NoSuchAlgorithmException(SecurityUtils.EDDSA + " provider not supported");
        }

        EdDSAPublicKeySpec keySpec = new EdDSAPublicKeySpec(prvKey.getSeed(), prvKey.getParams());
        KeyFactory factory = SecurityUtils.getKeyFactory(SecurityUtils.EDDSA);
        return EdDSAPublicKey.class.cast(factory.generatePublic(keySpec));
    }

    @Override
    public EdDSAPublicKey clonePublicKey(EdDSAPublicKey key) throws GeneralSecurityException {
        if (key == null) {
            return null;
        } else {
            return generatePublicKey(new EdDSAPublicKeySpec(key.getA(), key.getParams()));
        }
    }

    @Override
    public EdDSAPrivateKey clonePrivateKey(EdDSAPrivateKey key) throws GeneralSecurityException {
        if (key == null) {
            return null;
        } else {
            return generatePrivateKey(new EdDSAPrivateKeySpec(key.getSeed(), key.getParams()));
        }
    }

    @Override
    public KeyPairGenerator getKeyPairGenerator() throws GeneralSecurityException {
        return SecurityUtils.getKeyPairGenerator(SecurityUtils.EDDSA);
    }

    @Override
    public KeyFactory getKeyFactoryInstance() throws GeneralSecurityException {
        return SecurityUtils.getKeyFactory(SecurityUtils.EDDSA);
    }
}
