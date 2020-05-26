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

import net.i2p.crypto.eddsa.EdDSAPublicKey;
import org.apache.sshd.common.config.keys.impl.SkED25519PublicKeyEntryDecoder;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.u2f.SkED25519PublicKey;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SkED25519BufferPublicKeyParser extends AbstractBufferPublicKeyParser<SkED25519PublicKey> {
    public static final SkED25519BufferPublicKeyParser INSTANCE = new SkED25519BufferPublicKeyParser();

    public SkED25519BufferPublicKeyParser() {
        super(SkED25519PublicKey.class, SkED25519PublicKeyEntryDecoder.KEY_TYPE);
    }

    @Override
    public SkED25519PublicKey getRawPublicKey(String keyType, Buffer buffer) throws GeneralSecurityException {
        // The "sk-ssh-ed25519@openssh.com" keytype has the same format as the "ssh-ed25519" keytype with an appname on
        // the end
        PublicKey publicKey = ED25519BufferPublicKeyParser.INSTANCE.getRawPublicKey(KeyPairProvider.SSH_ED25519, buffer);
        String appName = buffer.getString();
        return new SkED25519PublicKey(appName, false, (EdDSAPublicKey) publicKey);
    }
}
