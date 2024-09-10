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
package org.apache.sshd.common.util.security.bouncycastle;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;

import org.apache.sshd.common.util.security.Decryptor;
import org.apache.sshd.common.util.security.SecurityProviderRegistrar;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

/**
 * Utility to decrypt an RFC 5958 PKCS#8 EncryptedPrivateKeyInfo.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum BouncyCastleEncryptedPrivateKeyInfoDecryptor implements Decryptor {

    INSTANCE;

    BouncyCastleEncryptedPrivateKeyInfoDecryptor() {
        // Empty
    }

    @Override
    public byte[] decrypt(byte[] encrypted, char[] password)
            throws GeneralSecurityException {
        SecurityProviderRegistrar registrar = SecurityUtils.getRegisteredProvider(SecurityUtils.BOUNCY_CASTLE);
        if (registrar == null) {
            throw new NoSuchProviderException(SecurityUtils.BOUNCY_CASTLE + " registrar not available");
        }
        try {
            JcePKCSPBEInputDecryptorProviderBuilder builder = new JcePKCSPBEInputDecryptorProviderBuilder();
            if (registrar.isNamedProviderUsed()) {
                builder.setProvider(registrar.getProviderName());
            } else {
                builder.setProvider(registrar.getSecurityProvider());
            }
            PKCS8EncryptedPrivateKeyInfo info = new PKCS8EncryptedPrivateKeyInfo(encrypted);
            return info.decryptPrivateKeyInfo(builder.build(password)).getEncoded("DER");
        } catch (PKCSException | IOException e) {
            throw new GeneralSecurityException(e);
        }
    }
}
