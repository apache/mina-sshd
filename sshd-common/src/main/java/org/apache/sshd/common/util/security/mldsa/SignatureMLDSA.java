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
package org.apache.sshd.common.util.security.mldsa;

import java.security.SignatureException;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.signature.AbstractSignature;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.MLDSAParameterSets;

/**
 * An ML-DSA signature in pure mode with an empty context.
 *
 * @see    <a href="https://datatracker.ietf.org/doc/draft-sfluhrer-ssh-mldsa/">draft-sfluhrer-ssh-mldsa</a>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SignatureMLDSA extends AbstractSignature {
    private final MLDSAParameterSets params;

    /**
     * Creates a signature for a parameter set.
     *
     * @param params the parameter set
     */
    public SignatureMLDSA(MLDSAParameterSets params) {
        super(Objects.requireNonNull(params, "No ML-DSA parameters provided").getJceName(), params.getSshName());
        this.params = params;
    }

    @Override
    public boolean verify(SessionContext session, byte[] sig) throws Exception {
        byte[] data = sig;
        String sshName = params.getSshName();
        Map.Entry<String, byte[]> encoding = extractEncodedSignature(data, sshName::equals);
        if (encoding != null) {
            String keyType = encoding.getKey();
            ValidateUtils.checkTrue(sshName.equals(keyType), "Mismatched key type: %s", keyType);
            data = encoding.getValue();
        }

        return doVerify(data);
    }

    @Override
    protected boolean doVerify(byte[] data) throws SignatureException {
        if (data == null || data.length != params.getSignatureSize()) {
            return false;
        }
        try {
            return super.doVerify(data);
        } catch (SignatureException e) {
            // The JDK provider reports an invalid hint encoding as an exception instead of returning false.
            return false;
        }
    }
}
