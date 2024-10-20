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

import java.security.*;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import org.apache.sshd.common.config.keys.PrivateKeyEntryDecoder;
import org.apache.sshd.common.config.keys.PublicKeyEntryDecoder;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.security.eddsa.generic.EdDSASupport;

public class I2pEdDSASupport implements EdDSASupport<EdDSAPublicKey, EdDSAPrivateKey> {

    public I2pEdDSASupport() {
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
    public Class<? extends PublicKey> getEDDSAPublicKeyType() {
        return EdDSASecurityProviderUtils.getEDDSAPublicKeyType();
    }

    @Override
    public Class<? extends PrivateKey> getEDDSAPrivateKeyType() {
        return EdDSASecurityProviderUtils.getEDDSAPrivateKeyType();
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
    public PublicKey recoverEDDSAPublicKey(PrivateKey key) throws GeneralSecurityException {
        return EdDSASecurityProviderUtils.recoverEDDSAPublicKey(key);
    }

    @Override
    public PublicKey generateEDDSAPublicKey(byte[] seed) throws GeneralSecurityException {
        return EdDSASecurityProviderUtils.generateEDDSAPublicKey(seed);
    }

    @Override
    public PrivateKey generateEDDSAPrivateKey(byte[] seed) throws GeneralSecurityException {
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

}
