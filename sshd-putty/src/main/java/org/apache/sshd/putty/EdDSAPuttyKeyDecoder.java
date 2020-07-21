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
package org.apache.sshd.putty;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.security.eddsa.EdDSASecurityProviderUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class EdDSAPuttyKeyDecoder extends AbstractPuttyKeyDecoder<EdDSAPublicKey, EdDSAPrivateKey> {
    public static final EdDSAPuttyKeyDecoder INSTANCE = new EdDSAPuttyKeyDecoder();

    public EdDSAPuttyKeyDecoder() {
        super(EdDSAPublicKey.class, EdDSAPrivateKey.class, Collections.singletonList(KeyPairProvider.SSH_ED25519));
    }

    @Override
    public Collection<KeyPair> loadKeyPairs(
            NamedResource resourceKey, PuttyKeyReader pubReader, PuttyKeyReader prvReader, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        if (!SecurityUtils.isEDDSACurveSupported()) {
            throw new NoSuchAlgorithmException(SecurityUtils.EDDSA + " provider not supported for " + resourceKey);
        }

        String keyType = pubReader.readString();
        if (!KeyPairProvider.SSH_ED25519.equals(keyType)) {
            throw new InvalidKeySpecException("Not an " + SecurityUtils.EDDSA + " key: " + keyType);
        }

        byte[] seed = pubReader.read(Short.MAX_VALUE); // reasonable max. allowed size
        PublicKey pubKey = EdDSASecurityProviderUtils.generateEDDSAPublicKey(seed);
        seed = prvReader.read(Short.MAX_VALUE); // reasonable max. allowed size
        PrivateKey prvKey = EdDSASecurityProviderUtils.generateEDDSAPrivateKey(seed);
        return Collections.singletonList(new KeyPair(pubKey, prvKey));
    }
}
