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
import java.security.interfaces.ECPublicKey;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.impl.SkECDSAPublicKeyEntryDecoder;
import org.apache.sshd.common.u2f.SkEcdsaPublicKey;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SkECBufferPublicKeyParser extends AbstractBufferPublicKeyParser<SkEcdsaPublicKey> {
    public static final SkECBufferPublicKeyParser INSTANCE = new SkECBufferPublicKeyParser();

    public SkECBufferPublicKeyParser() {
        super(SkEcdsaPublicKey.class, SkECDSAPublicKeyEntryDecoder.KEY_TYPE);
    }

    @Override
    public SkEcdsaPublicKey getRawPublicKey(String keyType, Buffer buffer) throws GeneralSecurityException {
        // The "sk-ecdsa-sha2-nistp256@openssh.com" keytype has the same format as the "ecdsa-sha2-nistp256" keytype
        // with an appname on the end
        ECPublicKey ecPublicKey = ECBufferPublicKeyParser.INSTANCE.getRawPublicKey(ECCurves.nistp256.getKeyType(), buffer);
        String appName = buffer.getString();
        return new SkEcdsaPublicKey(appName, false, ecPublicKey);
    }
}
