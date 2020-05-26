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
package org.apache.sshd.common.config.keys.loader;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.List;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DESPrivateKeyObfuscator extends AbstractPrivateKeyObfuscator {
    public static final int DEFAULT_KEY_LENGTH = 24 /* hardwired size for 3DES */;
    public static final List<Integer> AVAILABLE_KEY_LENGTHS = Collections.unmodifiableList(
            Collections.singletonList(
                    Integer.valueOf(DEFAULT_KEY_LENGTH)));
    public static final DESPrivateKeyObfuscator INSTANCE = new DESPrivateKeyObfuscator();

    public DESPrivateKeyObfuscator() {
        super("DES");
    }

    @Override
    public byte[] applyPrivateKeyCipher(
            byte[] bytes, PrivateKeyEncryptionContext encContext, boolean encryptIt)
            throws GeneralSecurityException, IOException {
        PrivateKeyEncryptionContext effContext = resolveEffectiveContext(encContext);
        byte[] keyValue = deriveEncryptionKey(effContext, DEFAULT_KEY_LENGTH);
        return applyPrivateKeyCipher(bytes, effContext, keyValue.length * Byte.SIZE, keyValue, encryptIt);
    }

    @Override
    public List<Integer> getSupportedKeySizes() {
        return AVAILABLE_KEY_LENGTHS;
    }

    @Override
    protected int resolveKeyLength(PrivateKeyEncryptionContext encContext) throws GeneralSecurityException {
        return DEFAULT_KEY_LENGTH;
    }

    @Override
    protected int resolveInitializationVectorLength(PrivateKeyEncryptionContext encContext) throws GeneralSecurityException {
        return 8;
    }

    public static final PrivateKeyEncryptionContext resolveEffectiveContext(PrivateKeyEncryptionContext encContext) {
        if (encContext == null) {
            return null;
        }

        String cipherName = encContext.getCipherName();
        String cipherType = encContext.getCipherType();
        PrivateKeyEncryptionContext effContext = encContext;
        if ("EDE3".equalsIgnoreCase(cipherType)) {
            cipherName += "ede";
            effContext = encContext.clone();
            effContext.setCipherName(cipherName);
        }

        return effContext;
    }
}
