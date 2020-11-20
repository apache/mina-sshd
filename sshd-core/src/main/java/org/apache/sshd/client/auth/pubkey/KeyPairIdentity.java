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
package org.apache.sshd.client.auth.pubkey;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.signature.SignatureFactoriesHolder;
import org.apache.sshd.common.signature.SignatureFactoriesManager;
import org.apache.sshd.common.signature.SignatureFactory;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Uses a {@link KeyPair} to generate the identity signature
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class KeyPairIdentity implements PublicKeyIdentity, SignatureFactoriesHolder {
    protected final KeyPair pair;
    private final List<NamedFactory<Signature>> signatureFactories;

    public KeyPairIdentity(SignatureFactoriesManager primary, SignatureFactoriesManager secondary, KeyPair pair) {
        this.signatureFactories = Collections.unmodifiableList(
                ValidateUtils.checkNotNullAndNotEmpty(
                        SignatureFactoriesManager.resolveSignatureFactories(primary, secondary),
                        "No available signature factories"));
        this.pair = Objects.requireNonNull(pair, "No key pair");
    }

    @Override
    public PublicKey getPublicKey() {
        return pair.getPublic();
    }

    @Override
    public List<NamedFactory<Signature>> getSignatureFactories() {
        return signatureFactories;
    }

    @Override
    public byte[] sign(SessionContext session, byte[] data) throws Exception {
        String keyType = KeyUtils.getKeyType(getPublicKey());
        // SSHD-1104 check if the key type is aliased
        NamedFactory<? extends Signature> factory = SignatureFactory.resolveSignatureFactory(keyType, getSignatureFactories());
        Signature verifier = (factory == null) ? null : factory.create();
        ValidateUtils.checkNotNull(verifier, "No signer could be located for key type=%s", keyType);
        verifier.initSigner(session, pair.getPrivate());
        verifier.update(session, data);
        return verifier.sign(session);
    }

    @Override
    public String toString() {
        PublicKey pubKey = getPublicKey();
        return getClass().getSimpleName()
               + " type=" + KeyUtils.getKeyType(pubKey)
               + ", factories=" + getSignatureFactoriesNameList()
               + ", fingerprint=" + KeyUtils.getFingerPrint(pubKey);
    }
}
