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

package org.apache.sshd.common.util.buffer.keys;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * TODO complete this when SSHD-440 is done
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ED25519BufferPublicKeyParser extends AbstractBufferPublicKeyParser<PublicKey> {
    public static final ED25519BufferPublicKeyParser INSTANCE = new ED25519BufferPublicKeyParser();

    public ED25519BufferPublicKeyParser() {
        super(PublicKey.class, KeyPairProvider.SSH_ED25519);
    }

    @Override
    public PublicKey getRawPublicKey(String keyType, Buffer buffer) throws GeneralSecurityException {
        ValidateUtils.checkTrue(isKeyTypeSupported(keyType), "Unsupported key type: %s", keyType);
        byte[] seed = buffer.getBytes();
        return SecurityUtils.generateEDDSAPublicKey(keyType, seed);
    }
}
