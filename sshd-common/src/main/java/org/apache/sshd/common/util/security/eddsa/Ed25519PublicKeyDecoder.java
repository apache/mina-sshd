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

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import org.apache.sshd.common.util.security.eddsa.generic.GenericEd25519PublicKeyDecoder;

/**
 * An implementation of {@link GenericEd25519PublicKeyDecoder} tied to the {@code net.i2p.crypto} EdDSA security
 * provider.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class Ed25519PublicKeyDecoder extends GenericEd25519PublicKeyDecoder<EdDSAPublicKey, EdDSAPrivateKey> {

    public static final Ed25519PublicKeyDecoder INSTANCE = new Ed25519PublicKeyDecoder();

    private Ed25519PublicKeyDecoder() {
        super(EdDSAPublicKey.class, EdDSAPrivateKey.class, new NetI2pCryptoEdDSASupport());
    }

    public static byte[] getSeedValue(EdDSAPublicKey key) {
        // a bit of reverse-engineering on the EdDSAPublicKeySpec
        return (key == null) ? null : key.getAbyte();
    }
}
