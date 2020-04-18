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

import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.keys.OpenSshCertificateImpl;
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

        OpenSshCertificateImpl certificate = new OpenSshCertificateImpl();
        certificate.setKeyType(keyType);

        certificate.setNonce(buffer.getBytes());

        String rawKeyType = certificate.getRawKeyType();
        certificate.setServerHostKey(DEFAULT.getRawPublicKey(rawKeyType, buffer));

        certificate.setSerial(buffer.getLong());
        certificate.setType(buffer.getInt());

        certificate.setId(buffer.getString());

        certificate.setPrincipals(new ByteArrayBuffer(buffer.getBytes()).getStringList(false));
        certificate.setValidAfter(buffer.getLong());
        certificate.setValidBefore(buffer.getLong());

        certificate.setCriticalOptions(buffer.getNameList());
        certificate.setExtensions(buffer.getNameList());

        certificate.setReserved(buffer.getString());

        try {
            certificate.setCaPubKey(buffer.getPublicKey());
        } catch (SshException ex) {
            throw new GeneralSecurityException("Could not parse public CA key with ID: " + certificate.getId(), ex);
        }

        certificate.setMessage(buffer.getBytesConsumed());
        certificate.setSignature(buffer.getBytes());

        if (buffer.rpos() != buffer.wpos()) {
            throw new GeneralSecurityException("KeyExchange signature verification failed, got more data than expected: "
                + buffer.rpos() + ", actual: " + buffer.wpos() + ". ID of the ca certificate: " + certificate.getId());
        }

        return certificate;
    }
}
