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
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DSSPuttyKeyDecoder extends AbstractPuttyKeyDecoder<DSAPublicKey, DSAPrivateKey> {
    public static final DSSPuttyKeyDecoder INSTANCE = new DSSPuttyKeyDecoder();

    public DSSPuttyKeyDecoder() {
        super(DSAPublicKey.class, DSAPrivateKey.class, Collections.singletonList(KeyPairProvider.SSH_DSS));
    }

    @Override
    public Collection<KeyPair> loadKeyPairs(
            NamedResource resourceKey, PuttyKeyReader pubReader, PuttyKeyReader prvReader, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        pubReader.skip(); // skip version

        BigInteger p = pubReader.readInt();
        BigInteger q = pubReader.readInt();
        BigInteger g = pubReader.readInt();
        BigInteger y = pubReader.readInt();
        BigInteger x = prvReader.readInt();
        KeyFactory kf = SecurityUtils.getKeyFactory(KeyUtils.DSS_ALGORITHM);
        PublicKey pubKey = kf.generatePublic(new DSAPublicKeySpec(y, p, q, g));
        PrivateKey prvKey = kf.generatePrivate(new DSAPrivateKeySpec(x, p, q, g));
        return Collections.singletonList(new KeyPair(pubKey, prvKey));
    }
}
