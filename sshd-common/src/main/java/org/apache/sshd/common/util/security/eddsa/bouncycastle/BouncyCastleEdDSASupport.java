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

package org.apache.sshd.common.util.security.eddsa.bouncycastle;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;

import org.apache.sshd.common.config.keys.PrivateKeyEntryDecoder;
import org.apache.sshd.common.config.keys.PublicKeyEntryDecoder;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.security.eddsa.generic.EdDSASupport;
import org.apache.sshd.common.util.security.eddsa.generic.GenericEd25519PublicKeyDecoder;
import org.apache.sshd.common.util.security.eddsa.generic.GenericOpenSSHEd25519PrivateKeyEntryDecoder;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;

public class BouncyCastleEdDSASupport implements EdDSASupport {

    public BouncyCastleEdDSASupport() {
        super();
    }

    @Override
    public PublicKeyEntryDecoder getEDDSAPublicKeyEntryDecoder() {
        return new GenericEd25519PublicKeyDecoder(this);
    }

    @Override
    public PrivateKeyEntryDecoder getOpenSSHEDDSAPrivateKeyEntryDecoder() {
        return new GenericOpenSSHEd25519PrivateKeyEntryDecoder(this);
    }

    @Override
    public EdDSAPublicKey recoverEDDSAPublicKey(PrivateKey key) throws GeneralSecurityException {
        if (!(key instanceof EdDSAPrivateKey)) {
            throw new InvalidKeyException("Private key is not " + SecurityUtils.EDDSA);
        }
        EdDSAPrivateKey edDSAKey = (EdDSAPrivateKey) key;
        return edDSAKey.getPublicKey();
    }

}
