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
import java.io.StreamCorruptedException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;

import org.apache.sshd.common.config.keys.PrivateKeyEntryDecoder;
import org.apache.sshd.common.config.keys.PublicKeyEntryDecoder;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.io.der.ASN1Object;
import org.apache.sshd.common.util.io.der.ASN1Type;
import org.apache.sshd.common.util.io.der.DERParser;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * Provides generic operations required of a security provider to support EdDSA and Ed25519.
 *
 * @param  <PUB> type of the public key supported by the security provider
 * @param  <PRV> type of the private key supported by the security provider
 * @author       <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface EdDSASupport<PUB extends PublicKey, PRV extends PrivateKey> {

    int KEY_SIZE = 256;

    /**
     * @see <A HREF="https://tools.ietf.org/html/rfc8410#section-3">RFC8412 section 3</A>
     */
    String ED25519_OID = "1.3.101.112";

    /**
     * @param  keyData the raw private key bytes.
     * @return         a {@link KeyPair} from the given raw private key data.
     */
    static KeyPair decodeEd25519KeyPair(byte[] keyData) throws IOException, GeneralSecurityException {
        PrivateKey privateKey = decodeEdDSAPrivateKey(keyData);
        PublicKey publicKey = SecurityUtils.recoverEDDSAPublicKey(privateKey);
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * @param  keyData the raw private key bytes.
     * @return         the associated private key.
     */
    static PrivateKey decodeEdDSAPrivateKey(byte[] keyData) throws IOException, GeneralSecurityException {
        try (DERParser parser = new DERParser(keyData)) {
            ASN1Object obj = parser.readObject();
            if (obj == null) {
                throw new StreamCorruptedException("Missing key data container");
            }

            ASN1Type objType = obj.getObjType();
            if (objType != ASN1Type.OCTET_STRING) {
                throw new StreamCorruptedException("Mismatched key data container type: " + objType);
            }

            return SecurityUtils.generateEDDSAPrivateKey(KeyPairProvider.SSH_ED25519, obj.getValue());
        }
    }

    /**
     * @return the public key entry decoder implementation associated with the security provider.
     */
    PublicKeyEntryDecoder<PUB, PRV> getEDDSAPublicKeyEntryDecoder();

    /**
     * @return the private key entry decoder implementation associated with the security provider.
     */
    PrivateKeyEntryDecoder<PUB, PRV> getOpenSSHEDDSAPrivateKeyEntryDecoder();

    /**
     * @return the signature implementation associated with the security provider.
     */
    Signature getEDDSASigner();

    /**
     * @param  key the key to get the size of.
     * @return     the size of the key if it is an EdDSA key, -1 otherwise.
     */
    int getEDDSAKeySize(Key key);

    /**
     * @return the public key class type associated with the security provider.
     */
    Class<PUB> getEDDSAPublicKeyType();

    /**
     * @return the private key class type associated with the security provider.
     */
    Class<PRV> getEDDSAPrivateKeyType();

    /**
     * @param  k1 the first key
     * @param  k2 the second key
     * @return    {@code true} if both keys are instances of the public key type associated with the security provider
     *            and they are equal.
     */
    boolean compareEDDSAPPublicKeys(PublicKey k1, PublicKey k2);

    /**
     * @param  k1 the first key
     * @param  k2 the second key
     * @return    {@code true} if both keys are instances of the private key type associated with the security provider
     *            and they are equal.
     */
    boolean compareEDDSAPrivateKeys(PrivateKey k1, PrivateKey k2);

    /**
     * @param  key the private key
     * @return     the public key associated with the private key.
     */
    PUB recoverEDDSAPublicKey(PrivateKey key) throws GeneralSecurityException;

    /**
     * @param  seed the raw public key bytes
     * @return      the associated public key
     */
    PUB generateEDDSAPublicKey(byte[] seed) throws GeneralSecurityException;

    /**
     * @param  seed the raw private key bytes
     * @return      the associated private key
     */
    PRV generateEDDSAPrivateKey(byte[] seed) throws GeneralSecurityException, IOException;

    /**
     * @param  buffer the buffer to insert the public key into
     * @param  key    the public key to be inserted into the buffer
     * @return        the buffer that was passed in
     * @param  <B>    type of the buffer
     */
    <B extends Buffer> B putRawEDDSAPublicKey(B buffer, PublicKey key);

    /**
     * @param  buffer the buffer to insert the keys into
     * @param  pubKey the public key to be inserted into the buffer
     * @param  prvKey the private key to be inserted into the buffer
     * @return        the buffer that was passed in
     * @param  <B>    type of the buffer
     */
    <B extends Buffer> B putEDDSAKeyPair(B buffer, PublicKey pubKey, PrivateKey prvKey);

    /**
     * @param  publicKey the public key
     * @return           a key spec from the public key
     */
    KeySpec createPublicKeySpec(PUB publicKey);

    /**
     * @param  privateKey the private key
     * @return            a key spec from the private key
     */
    KeySpec createPrivateKeySpec(PRV privateKey);

    /**
     * @param  publicKey the public key
     * @return           the raw public key bytes associated with the key
     */
    byte[] getPublicKeyData(PUB publicKey);

    /**
     * @param  privateKey the private key
     * @return            the raw private key bytes associated with the key
     */
    byte[] getPrivateKeyData(PRV privateKey) throws IOException;

    /**
     * @return the algorithm name used by the provider's {@link java.security.KeyFactory}.
     */
    String getKeyFactoryAlgorithm();

}
