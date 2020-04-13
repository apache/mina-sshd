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
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

public class OpenSSHCertPublicKeyParser extends AbstractBufferPublicKeyParser<PublicKey> {

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

        byte[] nonce = buffer.getBytes();

        String rawKeyType = OpenSshCertificate.getRawKeyType(keyType);
        PublicKey publicKey = DEFAULT.getRawPublicKey(rawKeyType, buffer);

        long serial = buffer.getLong();
        int userOrHostType = buffer.getInt();

        String id = buffer.getString();

        List<String> vPrincipals = new ByteArrayBuffer(buffer.getBytes()).getNameList();
        long vAfter = buffer.getLong();
        long vBefore = buffer.getLong();

        List<String> criticalOptions = buffer.getNameList();
        List<String> extensions = buffer.getNameList();

        String reserved = buffer.getString();

        PublicKey signatureKey;
        try {
            signatureKey = buffer.getPublicKey();
        } catch (SshException ex) {
            throw new GeneralSecurityException("Could not parse public CA key.", ex);
        }

        byte[] message = buffer.getBytesConsumed();
        byte[] signature = buffer.getBytes();

        if (buffer.rpos() != buffer.wpos()) {
            throw new GeneralSecurityException("KeyExchange signature verification failed, got more data than expected: "
                + buffer.rpos() + ", actual: " + buffer.wpos());
        }

        return OpenSshCertificate.OpenSshPublicKeyBuilder.anOpenSshCertificate()
            .withKeyType(keyType)
            .withNonce(nonce)
            .withServerHostPublicKey(publicKey)
            .withSerial(serial)
            .withType(userOrHostType)
            .withId(id)
            .withPrincipals(vPrincipals)
            .withValidAfter(vAfter)
            .withValidBefore(vBefore)
            .withCriticalOptions(criticalOptions)
            .withExtensions(extensions)
            .withReserved(reserved)
            .withCaPubKey(signatureKey)
            .withMessage(message)
            .withSignature(signature)
            .build();
    }
}
