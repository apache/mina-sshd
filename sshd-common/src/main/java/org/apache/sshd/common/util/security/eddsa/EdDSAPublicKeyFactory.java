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
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.PublicKeyFactory;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class EdDSAPublicKeyFactory implements PublicKeyFactory {

    public static final PublicKeyFactory INSTANCE = new EdDSAPublicKeyFactory();

    private EdDSAPublicKeyFactory() {
        super();
    }

    @Override
    public PublicKey getPublicKey(PrivateKey key) {
        ValidateUtils.checkTrue(SecurityUtils.isEDDSACurveSupported(), SecurityUtils.EDDSA + " not supported");
        if (!(key instanceof EdDSAPrivateKey)) {
            return null;
        }

        EdDSAPrivateKey prvKey = (EdDSAPrivateKey) key;
        EdDSAPublicKeySpec keySpec = new EdDSAPublicKeySpec(prvKey.getAbyte(), prvKey.getParams());
        KeyFactory factory;
        try {
            factory = SecurityUtils.getKeyFactory(SecurityUtils.ED25519);
            return factory.generatePublic(keySpec);
        } catch (GeneralSecurityException e) {
            return null;
        }
    }

}
