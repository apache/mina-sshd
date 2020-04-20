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
import java.util.Collection;
import java.util.Objects;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.signature.SignatureFactoriesManager;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Uses a {@link KeyPair} to generate the identity signature
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class KeyPairIdentity implements PublicKeyIdentity {
    private final KeyPair pair;
    private final Collection<NamedFactory<Signature>> signatureFactories;

    public KeyPairIdentity(SignatureFactoriesManager primary, SignatureFactoriesManager secondary, KeyPair pair) {
        this.signatureFactories = ValidateUtils.checkNotNullAndNotEmpty(
                SignatureFactoriesManager.resolveSignatureFactories(primary, secondary),
                "No available signature factories");
        this.pair = Objects.requireNonNull(pair, "No key pair");
    }

    @Override
    public PublicKey getPublicKey() {
        return pair.getPublic();
    }

    @Override
    public byte[] sign(SessionContext session, byte[] data) throws Exception {
        String keyType = KeyUtils.getKeyType(getPublicKey());
        Signature verifier = ValidateUtils.checkNotNull(
                NamedFactory.create(signatureFactories, keyType),
                "No signer could be located for key type=%s",
                keyType);
        verifier.initSigner(session, pair.getPrivate());
        verifier.update(session, data);
        return verifier.sign(session);
    }

    @Override
    public String toString() {
        PublicKey pubKey = getPublicKey();
        return getClass().getSimpleName()
               + " type=" + KeyUtils.getKeyType(pubKey)
               + ", factories=" + NamedResource.getNames(signatureFactories)
               + ", fingerprint=" + KeyUtils.getFingerPrint(pubKey);
    }
}
