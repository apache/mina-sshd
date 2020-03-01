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

import org.apache.sshd.common.config.keys.impl.SkED25519PublicKeyEntryDecoder;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.security.SecurityUtils;

public class SignatureSkED25519 extends AbstractSecurityKeySignature {

    public static final String ALGORITHM = "ED25519-SK";

    public SignatureSkED25519() {
        super(SkED25519PublicKeyEntryDecoder.KEY_TYPE);
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }

    @Override
    protected String getSignatureKeyType() {
        return KeyPairProvider.SSH_ED25519;
    }

    @Override
    protected Signature getDelegateSignature() {
        return SecurityUtils.getEDDSASigner();
    }
}
