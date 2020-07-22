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
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
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
public class RSAPuttyKeyDecoder extends AbstractPuttyKeyDecoder<RSAPublicKey, RSAPrivateKey> {
    public static final RSAPuttyKeyDecoder INSTANCE = new RSAPuttyKeyDecoder();

    public RSAPuttyKeyDecoder() {
        super(RSAPublicKey.class, RSAPrivateKey.class, Collections.singletonList(KeyPairProvider.SSH_RSA));
    }

    @Override
    public Collection<KeyPair> loadKeyPairs(
            NamedResource resourceKey, PuttyKeyReader pubReader, PuttyKeyReader prvReader, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        pubReader.skip(); // skip version

        KeyFactory kf = SecurityUtils.getKeyFactory(KeyUtils.RSA_ALGORITHM);
        BigInteger publicExp = pubReader.readInt();
        BigInteger modulus = pubReader.readInt();
        PublicKey pubKey = kf.generatePublic(new RSAPublicKeySpec(modulus, publicExp));

        BigInteger privateExp = prvReader.readInt();
        BigInteger primeP = prvReader.readInt();
        BigInteger primeQ = prvReader.readInt();
        BigInteger crtCoef = prvReader.readInt();
        BigInteger primeExponentP = privateExp.mod(primeP.subtract(BigInteger.ONE));
        BigInteger primeExponentQ = privateExp.mod(primeQ.subtract(BigInteger.ONE));
        RSAPrivateKeySpec prvSpec = new RSAPrivateCrtKeySpec(
                modulus, publicExp, privateExp, primeP, primeQ, primeExponentP, primeExponentQ, crtCoef);
        PrivateKey prvKey = kf.generatePrivate(prvSpec);
        return Collections.singletonList(new KeyPair(pubKey, prvKey));
    }
}
