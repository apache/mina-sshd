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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.security.eddsa.generic.EdDSASupport;
import org.apache.sshd.common.util.security.eddsa.generic.GenericEd25519PEMResourceKeyParser;

/**
 * An implementation of {@link GenericEd25519PEMResourceKeyParser} tied to the {@code net.i2p.crypto} EdDSA security
 * provider.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class Ed25519PEMResourceKeyParser extends GenericEd25519PEMResourceKeyParser {

    public static final Ed25519PEMResourceKeyParser INSTANCE = new Ed25519PEMResourceKeyParser();

    public Ed25519PEMResourceKeyParser() {
        super();
    }

    public static EdDSAPrivateKey decodeEdDSAPrivateKey(byte[] keyData) throws IOException, GeneralSecurityException {
        return EdDSAPrivateKey.class.cast(EdDSASupport.decodeEdDSAPrivateKey(keyData));
    }

    public static EdDSAPrivateKey generateEdDSAPrivateKey(byte[] seed) throws GeneralSecurityException {
        if (!SecurityUtils.isEDDSACurveSupported()) {
            throw new NoSuchAlgorithmException(SecurityUtils.EDDSA + " provider not supported");
        }

        EdDSAParameterSpec params = EdDSANamedCurveTable.getByName(EdDSASecurityProviderUtils.CURVE_ED25519_SHA512);
        EdDSAPrivateKeySpec keySpec = new EdDSAPrivateKeySpec(seed, params);
        KeyFactory factory = SecurityUtils.getKeyFactory(SecurityUtils.EDDSA);
        return EdDSAPrivateKey.class.cast(factory.generatePrivate(keySpec));
    }
}
