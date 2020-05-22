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

import java.util.Map;

import net.i2p.crypto.eddsa.EdDSAEngine;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.signature.AbstractSignature;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SignatureEd25519 extends AbstractSignature {
    public SignatureEd25519() {
        super(EdDSAEngine.SIGNATURE_ALGORITHM);
    }

    @Override
    public boolean verify(SessionContext session, byte[] sig) throws Exception {
        byte[] data = sig;
        Map.Entry<String, byte[]> encoding
                = extractEncodedSignature(data, k -> KeyPairProvider.SSH_ED25519.equalsIgnoreCase(k));
        if (encoding != null) {
            String keyType = encoding.getKey();
            ValidateUtils.checkTrue(
                    KeyPairProvider.SSH_ED25519.equals(keyType), "Mismatched key type: %s", keyType);
            data = encoding.getValue();
        }

        return doVerify(data);
    }
}
