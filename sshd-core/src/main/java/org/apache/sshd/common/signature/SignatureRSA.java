/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.signature;

import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Signature;

/**
 * RSA <code>Signature</code>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SignatureRSA extends AbstractSignature {

    /**
     * A named factory for RSA <code>Signature</code>
     */
    public static class Factory implements NamedFactory<Signature> {

        public String getName() {
            return KeyPairProvider.SSH_RSA;
        }

        public Signature create() {
            return new SignatureRSA();
        }

    }

    public SignatureRSA() {
        super("SHA1withRSA");
    }

    public byte[] sign() throws Exception {
        return signature.sign();
    }

    public boolean verify(byte[] sig) throws Exception {
        sig = extractSig(sig);
        return signature.verify(sig);
    }

}
