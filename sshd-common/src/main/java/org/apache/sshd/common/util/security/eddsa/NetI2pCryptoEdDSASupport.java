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

import java.security.GeneralSecurityException;
import java.security.PrivateKey;

import net.i2p.crypto.eddsa.EdDSAPublicKey;
import org.apache.sshd.common.config.keys.PrivateKeyEntryDecoder;
import org.apache.sshd.common.config.keys.PublicKeyEntryDecoder;
import org.apache.sshd.common.util.security.eddsa.generic.EdDSASupport;

public class NetI2pCryptoEdDSASupport implements EdDSASupport {

    public NetI2pCryptoEdDSASupport() {
        super();
    }

    @Override
    public PublicKeyEntryDecoder getEDDSAPublicKeyEntryDecoder() {
        return Ed25519PublicKeyDecoder.INSTANCE;
    }

    @Override
    public PrivateKeyEntryDecoder getOpenSSHEDDSAPrivateKeyEntryDecoder() {
        return OpenSSHEd25519PrivateKeyEntryDecoder.INSTANCE;
    }

    @Override
    public EdDSAPublicKey recoverEDDSAPublicKey(PrivateKey key) throws GeneralSecurityException {
        return EdDSASecurityProviderUtils.recoverEDDSAPublicKey(key);
    }

}
