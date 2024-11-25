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
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.common.config.keys.KeyEntryResolver;
import org.apache.sshd.common.config.keys.impl.AbstractPublicKeyEntryDecoder;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class GenericEd25519PublicKeyDecoder<PUB extends PublicKey, PRV extends PrivateKey>
        extends AbstractPublicKeyEntryDecoder<PUB, PRV> {
    public static final int MAX_ALLOWED_SEED_LEN = 1024; // in reality it is much less than this

    protected final EdDSASupport<PUB, PRV> edDSASupport;

    public GenericEd25519PublicKeyDecoder(Class<PUB> pubType, Class<PRV> prvType, EdDSASupport<PUB, PRV> edDSASupport) {
        super(pubType, prvType, Collections.singletonList(KeyPairProvider.SSH_ED25519));
        this.edDSASupport = edDSASupport;
    }

    @Override
    public PUB clonePublicKey(PUB key) throws GeneralSecurityException {
        if (key == null) {
            return null;
        } else {
            return generatePublicKey(edDSASupport.createPublicKeySpec(key));
        }
    }

    @Override
    public PRV clonePrivateKey(PRV key) throws GeneralSecurityException {
        if (key == null) {
            return null;
        } else {
            return generatePrivateKey(edDSASupport.createPrivateKeySpec(key));
        }
    }

    @Override
    public KeyPairGenerator getKeyPairGenerator() throws GeneralSecurityException {
        return SecurityUtils.getKeyPairGenerator(SecurityUtils.EDDSA);
    }

    @Override
    public String encodePublicKey(OutputStream s, PUB key) throws IOException {
        Objects.requireNonNull(key, "No public key provided");
        KeyEntryResolver.encodeString(s, KeyPairProvider.SSH_ED25519);
        byte[] seed = edDSASupport.getPublicKeyData(key);
        KeyEntryResolver.writeRLEBytes(s, seed);
        return KeyPairProvider.SSH_ED25519;
    }

    @Override
    public KeyFactory getKeyFactoryInstance() throws GeneralSecurityException {
        return SecurityUtils.getKeyFactory(SecurityUtils.EDDSA);
    }

    @Override
    public PUB decodePublicKey(
            SessionContext session, String keyType, InputStream keyData, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        byte[] seed = KeyEntryResolver.readRLEBytes(keyData, MAX_ALLOWED_SEED_LEN);
        return edDSASupport.generateEDDSAPublicKey(seed);
    }

}
