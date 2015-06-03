/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.common.config.keys;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collections;

import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class RSAPublicKeyDecoder extends AbstractPublicKeyEntryDecoder<RSAPublicKey> {
    public static final RSAPublicKeyDecoder INSTANCE = new RSAPublicKeyDecoder();

    public RSAPublicKeyDecoder() {
        super(RSAPublicKey.class, Collections.unmodifiableList(Collections.singletonList(KeyPairProvider.SSH_RSA)));
    }

    @Override
    public RSAPublicKey decodePublicKey(String keyType, InputStream keyData) throws IOException, GeneralSecurityException {
        if (!KeyPairProvider.SSH_RSA.equals(keyType)) { // just in case we were invoked directly
            throw new InvalidKeySpecException("Unepected key type: " + keyType);
        }

        BigInteger  e=decodeBigInt(keyData);
        BigInteger  n=decodeBigInt(keyData);

        return generatePublicKey(new RSAPublicKeySpec(n, e));
    }
    
    @Override
    public KeyFactory getKeyFactoryInstance() throws GeneralSecurityException {
        return SecurityUtils.getKeyFactory("RSA");
    }
}
