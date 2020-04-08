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
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.sshd.common.SshException;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.u2f.OpenSshPublicKey;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

public class OpenSSHCertPublicKeyParser extends AbstractBufferPublicKeyParser<PublicKey> {
    public static final int SSH_CERT_TYPE_USER = 1;
    public static final int SSH_CERT_TYPE_HOST = 2;

    public static final OpenSSHCertPublicKeyParser INSTANCE = new OpenSSHCertPublicKeyParser(PublicKey.class,
            Arrays.asList(
                    KeyPairProvider.SSH_RSA_CERT,
                    KeyPairProvider.SSH_DSS_CERT,
                    KeyPairProvider.SSH_ECDSA_SHA2_NISTP256_CERT,
                    KeyPairProvider.SSH_ECDSA_SHA2_NISTP384_CERT,
                    KeyPairProvider.SSH_ECDSA_SHA2_NISTP521_CERT,
                    KeyPairProvider.SSH_ED25519_CERT
            ));

    public OpenSSHCertPublicKeyParser(Class<PublicKey> keyClass, Collection<String> supported) {
        super(keyClass, supported);
    }

    @Override
    public PublicKey getRawPublicKey(String keyType, Buffer buffer) throws GeneralSecurityException {

        buffer.getString(); // nonce

        String realKeyType = keyType.split("@")[0].substring(0, keyType.indexOf("-cert"));
        PublicKey publicKey = DEFAULT.getRawPublicKey(realKeyType, buffer);

        long serial = buffer.getLong();
        int userOrHostType = buffer.getInt();

        String id = buffer.getString();

        List<String> vPrincipals = new ByteArrayBuffer(buffer.getBytes()).getNameList();
        long vAfter = buffer.getLong();
        long vBefore = buffer.getLong();

        List<String> criticalOptions = buffer.getNameList();
        List<String> extensions = buffer.getNameList();

        buffer.getString(); // reserved

        PublicKey signatureKey;
        try {
            signatureKey = buffer.getPublicKey();
        } catch (SshException ex) {
            throw new GeneralSecurityException("Could not parse public CA key.", ex);
        }

        return OpenSshPublicKey.OpenSshPublicKeyBuilder.anOpenSshPublicKey()
                .withCaPubKey(publicKey)
                .withSerial(serial)
                .withType(userOrHostType)
                .withId(id)
                .withPrincipals(vPrincipals)
                .withValidAfter(vAfter)
                .withValidBefore(vBefore)
                .withCriticalOptions(criticalOptions)
                .withExtensions(extensions)
                .withCaPubKey(signatureKey)
                .build();
    }
}
