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
package org.apache.sshd.common.signature;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.impl.SkECDSAPublicKeyEntryDecoder;

public class SignatureSkECDSA extends AbstractSecurityKeySignature {

    public static final String ALGORITHM = "ECDSA-SK";

    public SignatureSkECDSA() {
        super(SkECDSAPublicKeyEntryDecoder.KEY_TYPE);
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }

    @Override
    protected String getSignatureKeyType() {
        return ECCurves.nistp256.getKeyType();
    }

    @Override
    protected Signature getDelegateSignature() {
        return new SignatureECDSA.SignatureECDSA256();
    }

}
