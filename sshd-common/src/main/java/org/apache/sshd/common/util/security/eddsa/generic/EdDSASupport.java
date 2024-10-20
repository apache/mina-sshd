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
import java.security.*;

import org.apache.sshd.common.config.keys.PrivateKeyEntryDecoder;
import org.apache.sshd.common.config.keys.PublicKeyEntryDecoder;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.io.der.ASN1Object;
import org.apache.sshd.common.util.io.der.ASN1Type;
import org.apache.sshd.common.util.io.der.DERParser;
import org.apache.sshd.common.util.security.SecurityUtils;

public interface EdDSASupport<PUB extends PublicKey, PRV extends PrivateKey> {

    int KEY_SIZE = 256;

    /**
     * @see <A HREF="https://tools.ietf.org/html/rfc8410#section-3">RFC8412 section 3</A>
     */
    String ED25519_OID = "1.3.101.112";

    static KeyPair decodeEd25519KeyPair(byte[] keyData) throws IOException, GeneralSecurityException {
        PrivateKey privateKey = decodeEdDSAPrivateKey(keyData);
        PublicKey publicKey = SecurityUtils.recoverEDDSAPublicKey(privateKey);
        return new KeyPair(publicKey, privateKey);
    }

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

    PublicKeyEntryDecoder<PUB, PRV> getEDDSAPublicKeyEntryDecoder();

    PrivateKeyEntryDecoder<PUB, PRV> getOpenSSHEDDSAPrivateKeyEntryDecoder();

    Signature getEDDSASigner();

    int getEDDSAKeySize(Key key);

    Class<? extends PublicKey> getEDDSAPublicKeyType();

    Class<? extends PrivateKey> getEDDSAPrivateKeyType();

    boolean compareEDDSAPPublicKeys(PublicKey k1, PublicKey k2);

    boolean compareEDDSAPrivateKeys(PrivateKey k1, PrivateKey k2);

    PublicKey recoverEDDSAPublicKey(PrivateKey key) throws GeneralSecurityException;

    PublicKey generateEDDSAPublicKey(byte[] seed) throws GeneralSecurityException;

    PrivateKey generateEDDSAPrivateKey(byte[] seed) throws GeneralSecurityException, IOException;

    <B extends Buffer> B putRawEDDSAPublicKey(B buffer, PublicKey key);

    <B extends Buffer> B putEDDSAKeyPair(B buffer, PublicKey pubKey, PrivateKey prvKey);

}
