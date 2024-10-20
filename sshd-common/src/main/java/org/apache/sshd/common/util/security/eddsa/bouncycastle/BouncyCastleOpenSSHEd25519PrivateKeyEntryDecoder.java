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

package org.apache.sshd.common.util.security.eddsa.bouncycastle;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
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
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.jcajce.spec.OpenSSHPrivateKeySpec;
import org.bouncycastle.jcajce.spec.RawEncodedKeySpec;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BouncyCastleOpenSSHEd25519PrivateKeyEntryDecoder
        extends AbstractPrivateKeyEntryDecoder<EdDSAPublicKey, EdDSAPrivateKey> {
    public static final BouncyCastleOpenSSHEd25519PrivateKeyEntryDecoder INSTANCE
            = new BouncyCastleOpenSSHEd25519PrivateKeyEntryDecoder();
    private static final int PK_SIZE = 32;
    private static final int SK_SIZE = 32;
    private static final int KEYPAIR_SIZE = PK_SIZE + SK_SIZE;

    public BouncyCastleOpenSSHEd25519PrivateKeyEntryDecoder() {
        super(EdDSAPublicKey.class, EdDSAPrivateKey.class,
              Collections.unmodifiableList(
                      Collections.singletonList(
                              KeyPairProvider.SSH_ED25519)));
    }

    @Override
    public EdDSAPrivateKey decodePrivateKey(
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
            Ed25519PrivateKeyParameters parameters = new Ed25519PrivateKeyParameters(sk);
            PrivateKeyInfo info = PrivateKeyInfoFactory.createPrivateKeyInfo(parameters);
            EdDSAPrivateKey privateKey = generatePrivateKey(new PKCS8EncodedKeySpec(info.getEncoded()));

            // the private key class contains the calculated public key (Abyte)
            // pointers to the corresponding code:
            // EdDSAPrivateKeySpec.EdDSAPrivateKeySpec(byte[], EdDSAParameterSpec): A = spec.getB().scalarMultiply(a);
            // EdDSAPrivateKey.EdDSAPrivateKey(EdDSAPrivateKeySpec): this.Abyte = this.A.toByteArray();

            // we can now verify the generated pk matches the one we read
            if (!Arrays.equals(privateKey.getPublicKey().getPointEncoding(), pk)) {
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
    public String encodePrivateKey(SecureByteArrayOutputStream s, EdDSAPrivateKey key, EdDSAPublicKey pubKey)
            throws IOException {
        Objects.requireNonNull(key, "No private key provided");

        // ed25519 bernstein naming: pk .. public key, sk .. secret key
        // we are expected to write the following arrays (type:size):
        // [pk:32], [sk:32,pk:32]

        Ed25519PrivateKeyParameters parameters = (Ed25519PrivateKeyParameters) PrivateKeyFactory.createKey(key.getEncoded());
        byte[] sk = parameters.getEncoded();
        byte[] pk = key.getPublicKey().getPointEncoding();

        Objects.requireNonNull(sk, "No seed");

        byte[] keypair = new byte[KEYPAIR_SIZE];
        System.arraycopy(sk, 0, keypair, 0, SK_SIZE);
        System.arraycopy(pk, 0, keypair, SK_SIZE, PK_SIZE);

        KeyEntryResolver.writeRLEBytes(s, pk);
        KeyEntryResolver.writeRLEBytes(s, keypair);

        return KeyPairProvider.SSH_ED25519;
    }

    @Override
    public boolean isPublicKeyRecoverySupported() {
        return true;
    }

    @Override
    public EdDSAPublicKey recoverPublicKey(EdDSAPrivateKey prvKey) throws GeneralSecurityException {
        return (EdDSAPublicKey) SecurityUtils.recoverEDDSAPublicKey(prvKey);
    }

    @Override
    public EdDSAPublicKey clonePublicKey(EdDSAPublicKey key) throws GeneralSecurityException {
        if (key == null) {
            return null;
        } else {
            return generatePublicKey(new RawEncodedKeySpec(key.getPointEncoding()));
        }
    }

    @Override
    public EdDSAPrivateKey clonePrivateKey(EdDSAPrivateKey key) throws GeneralSecurityException {
        if (key == null) {
            return null;
        } else {
            return generatePrivateKey(new OpenSSHPrivateKeySpec(key.getEncoded()));
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
