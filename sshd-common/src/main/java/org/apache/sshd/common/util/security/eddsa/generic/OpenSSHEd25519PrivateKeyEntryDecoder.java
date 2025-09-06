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

package org.apache.sshd.common.util.security.eddsa.generic;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.Locale;
import java.util.Objects;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.KeyEntryResolver;
import org.apache.sshd.common.config.keys.impl.AbstractPrivateKeyEntryDecoder;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.output.SecureByteArrayOutputStream;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class OpenSSHEd25519PrivateKeyEntryDecoder extends AbstractPrivateKeyEntryDecoder {

    public static final OpenSSHEd25519PrivateKeyEntryDecoder INSTANCE = new OpenSSHEd25519PrivateKeyEntryDecoder();

    private static final int PK_SIZE = 32;
    private static final int SK_SIZE = 32;
    private static final int KEYPAIR_SIZE = PK_SIZE + SK_SIZE;

    public OpenSSHEd25519PrivateKeyEntryDecoder() {
        super(Collections.singletonList(KeyPairProvider.SSH_ED25519));
    }

    @Override
    public PrivateKey decodePrivateKey(
            SessionContext session, String keyType, FilePasswordProvider passwordProvider, InputStream keyData)
            throws IOException, GeneralSecurityException {
        if (!KeyPairProvider.SSH_ED25519.equals(keyType)) {
            throw new InvalidKeyException("Unsupported key type: " + keyType);
        }

        if (!SecurityUtils.isEDDSACurveSupported()) {
            throw new NoSuchAlgorithmException(SecurityUtils.EDDSA + " provider not supported");
        }

        // ed25519 bernstein naming: pk .. public key, sk .. secret key
        // we expect to find two byte arrays with the following structure (type:size):
        // [pk:32], [sk:32,pk:32]

        byte[] pk = GenericUtils.EMPTY_BYTE_ARRAY;
        byte[] keypair = GenericUtils.EMPTY_BYTE_ARRAY;
        try {
            pk = KeyEntryResolver.readRLEBytes(keyData, PK_SIZE * 2);
            keypair = KeyEntryResolver.readRLEBytes(keyData, KEYPAIR_SIZE * 2);
            if (pk.length != PK_SIZE) {
                throw new InvalidKeyException(
                        String.format(Locale.ENGLISH, "Unexpected pk size: %s (expected %s)", pk.length, PK_SIZE));
            }

            if (keypair.length != KEYPAIR_SIZE) {
                throw new InvalidKeyException(
                        String.format(Locale.ENGLISH, "Unexpected keypair size: %s (expected %s)", keypair.length,
                                KEYPAIR_SIZE));
            }

            // verify that the keypair contains the expected pk
            // yes, it's stored redundant, this seems to mimic the output structure of the keypair generation interface
            if (!Arrays.equals(pk, Arrays.copyOfRange(keypair, SK_SIZE, KEYPAIR_SIZE))) {
                throw new InvalidKeyException("Keypair did not contain the public key.");
            }

            byte[] sk = Arrays.copyOf(keypair, SK_SIZE);
            PrivateKey privateKey = EdDSAUtils.getPrivateKey(sk);

            // we can now verify the generated pk matches the one we read
            PublicKey recoveredPk = recoverPublicKey(privateKey);
            if (recoveredPk != null && !Arrays.equals(EdDSAUtils.getBytes(recoveredPk), pk)) {
                throw new InvalidKeyException("The provided pk does NOT match the computed pk for the given sk.");
            }

            return privateKey;
        } finally {
            // get rid of sensitive data a.s.a.p
            Arrays.fill(pk, (byte) 0);
            Arrays.fill(keypair, (byte) 0);
        }
    }

    @Override
    public String encodePrivateKey(SecureByteArrayOutputStream s, PrivateKey key, PublicKey pubKey)
            throws IOException {
        Objects.requireNonNull(key, "No private key provided");

        // ed25519 bernstein naming: pk .. public key, sk .. secret key
        // we are expected to write the following arrays (type:size):
        // [pk:32], [sk:32,pk:32]

        byte[] sk = null;
        try {
            byte[] pk = EdDSAUtils.getBytes(pubKey);
            sk = EdDSAUtils.getBytes(key);

            Objects.requireNonNull(sk, "No seed");

            byte[] keypair = new byte[KEYPAIR_SIZE];
            System.arraycopy(sk, 0, keypair, 0, SK_SIZE);
            System.arraycopy(pk, 0, keypair, SK_SIZE, PK_SIZE);

            KeyEntryResolver.writeRLEBytes(s, pk);
            KeyEntryResolver.writeRLEBytes(s, keypair);
        } finally {
            if (sk != null) {
                Arrays.fill(sk, (byte) 0);
            }
        }
        return KeyPairProvider.SSH_ED25519;
    }

    @Override
    public boolean isPublicKeyRecoverySupported() {
        return true;
    }

    @Override
    public PublicKey recoverPublicKey(PrivateKey prvKey) throws GeneralSecurityException {
        return SecurityUtils.recoverEDDSAPublicKey(prvKey);
    }

    @Override
    public KeyPairGenerator getKeyPairGenerator() throws GeneralSecurityException {
        return SecurityUtils.getKeyPairGenerator(SecurityUtils.ED25519);
    }

    @Override
    public KeyFactory getKeyFactoryInstance() throws GeneralSecurityException {
        return SecurityUtils.getKeyFactory(SecurityUtils.ED25519);
    }
}
