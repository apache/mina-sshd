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
package org.apache.sshd.common.util.security.bouncycastle;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.sshd.common.util.security.PublicKeyFactory;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;

public final class BouncyCastlePublicKeyFactory implements PublicKeyFactory {

    public static final PublicKeyFactory INSTANCE = new BouncyCastlePublicKeyFactory();

    private BouncyCastlePublicKeyFactory() {
        super();
    }

    @Override
    public PublicKey getPublicKey(PrivateKey key) {
        if (SecurityUtils.ED25519.equals(key.getAlgorithm())) {
            return getPublicEdDSAKey(key);
        }
        return null;
    }

    public PublicKey getPublicEdDSAKey(PrivateKey key) {
        if (key instanceof EdDSAPrivateKey) {
            EdDSAPrivateKey edDSAKey = (EdDSAPrivateKey) key;
            return edDSAKey.getPublicKey();
        }
        return null;
    }
}
