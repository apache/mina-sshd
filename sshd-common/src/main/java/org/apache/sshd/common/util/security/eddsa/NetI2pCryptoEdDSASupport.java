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
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.apache.sshd.common.config.keys.PrivateKeyEntryDecoder;
import org.apache.sshd.common.config.keys.PublicKeyEntryDecoder;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.security.eddsa.generic.EdDSASupport;

public class NetI2pCryptoEdDSASupport implements EdDSASupport<EdDSAPublicKey, EdDSAPrivateKey> {

    public NetI2pCryptoEdDSASupport() {
        super();
    }

    @Override
    public PublicKeyEntryDecoder<EdDSAPublicKey, EdDSAPrivateKey> getEDDSAPublicKeyEntryDecoder() {
        return Ed25519PublicKeyDecoder.INSTANCE;
    }

    @Override
    public PrivateKeyEntryDecoder<EdDSAPublicKey, EdDSAPrivateKey> getOpenSSHEDDSAPrivateKeyEntryDecoder() {
        return OpenSSHEd25519PrivateKeyEntryDecoder.INSTANCE;
    }

    @Override
    public Signature getEDDSASigner() {
        return EdDSASecurityProviderUtils.getEDDSASignature();
    }

    @Override
    public int getEDDSAKeySize(Key key) {
        return EdDSASecurityProviderUtils.getEDDSAKeySize(key);
    }

    @Override
    public Class<EdDSAPublicKey> getEDDSAPublicKeyType() {
        return EdDSAPublicKey.class;
    }

    @Override
    public Class<EdDSAPrivateKey> getEDDSAPrivateKeyType() {
        return EdDSAPrivateKey.class;
    }

    @Override
    public boolean compareEDDSAPPublicKeys(PublicKey k1, PublicKey k2) {
        return EdDSASecurityProviderUtils.compareEDDSAPPublicKeys(k1, k2);
    }

    @Override
    public boolean compareEDDSAPrivateKeys(PrivateKey k1, PrivateKey k2) {
        return EdDSASecurityProviderUtils.compareEDDSAPrivateKeys(k1, k2);
    }

    @Override
    public EdDSAPublicKey recoverEDDSAPublicKey(PrivateKey key) throws GeneralSecurityException {
        return EdDSASecurityProviderUtils.recoverEDDSAPublicKey(key);
    }

    @Override
    public EdDSAPublicKey generateEDDSAPublicKey(byte[] seed) throws GeneralSecurityException {
        return (EdDSAPublicKey) EdDSASecurityProviderUtils.generateEDDSAPublicKey(seed);
    }

    @Override
    public EdDSAPrivateKey generateEDDSAPrivateKey(byte[] seed) throws GeneralSecurityException {
        return Ed25519PEMResourceKeyParser.generateEdDSAPrivateKey(seed);
    }

    @Override
    public <B extends Buffer> B putRawEDDSAPublicKey(B buffer, PublicKey key) {
        return EdDSASecurityProviderUtils.putRawEDDSAPublicKey(buffer, key);
    }

    @Override
    public <B extends Buffer> B putEDDSAKeyPair(B buffer, PublicKey pubKey, PrivateKey prvKey) {
        return EdDSASecurityProviderUtils.putEDDSAKeyPair(buffer, pubKey, prvKey);
    }

    @Override
    public KeySpec createPublicKeySpec(EdDSAPublicKey publicKey) {
        return new EdDSAPublicKeySpec(publicKey.getA(), publicKey.getParams());
    }

    @Override
    public KeySpec createPrivateKeySpec(EdDSAPrivateKey privateKey) {
        return new EdDSAPrivateKeySpec(privateKey.getSeed(), privateKey.getParams());
    }

    @Override
    public byte[] getPublicKeyData(EdDSAPublicKey publicKey) {
        return publicKey == null ? null : publicKey.getAbyte();
    }

    @Override
    public byte[] getPrivateKeyData(EdDSAPrivateKey privateKey) throws IOException {
        return privateKey.getSeed();
    }

    @Override
    public String getKeyFactoryAlgorithm() {
        return SecurityUtils.EDDSA;
    }
}
