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

package org.apache.sshd.common.config.keys.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.buffer.keys.OpenSSHCertPublicKeyParser;
import org.apache.sshd.common.util.io.IoUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class OpenSSHCertificateDecoder extends AbstractPublicKeyEntryDecoder {
    public static final OpenSSHCertificateDecoder INSTANCE = new OpenSSHCertificateDecoder();

    public OpenSSHCertificateDecoder() {
        super(Collections.unmodifiableList(Arrays.asList(
                KeyUtils.RSA_SHA256_CERT_TYPE_ALIAS,
                KeyUtils.RSA_SHA512_CERT_TYPE_ALIAS,
                KeyPairProvider.SSH_RSA_CERT,
                KeyPairProvider.SSH_DSS_CERT,
                KeyPairProvider.SSH_ED25519_CERT,
                KeyPairProvider.SSH_ECDSA_SHA2_NISTP256_CERT,
                KeyPairProvider.SSH_ECDSA_SHA2_NISTP384_CERT,
                KeyPairProvider.SSH_ECDSA_SHA2_NISTP521_CERT)));
    }

    @Override
    public OpenSshCertificate decodePublicKey(
            SessionContext session, String keyType, InputStream keyData, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        // keyType has already been read from keyData, but getRawPublicKey() relies on
        // being able to use the bytes already consumed from the buffer to set the
        // "message" of the certificate, which is supposed to be the raw data that was
        // signed. This must include the key type. Hence create a buffer that contains
        // this key type again, but that is positioned for reading after that key type.
        ByteArrayBuffer buffer = new ByteArrayBuffer();
        buffer.putString(keyType);
        buffer.putRawBytes(IoUtils.toByteArray(keyData));
        buffer.getString(); // Skip the key type just prepended
        return OpenSSHCertPublicKeyParser.INSTANCE.getRawPublicKey(keyType, buffer);
    }

    @Override
    public String encodePublicKey(OutputStream s, PublicKey k) throws IOException {
        OpenSshCertificate key = ValidateUtils.checkInstanceOf(k, OpenSshCertificate.class,
                "Key must be an OpenSshCertificate");
        Objects.requireNonNull(key, "No public key provided");

        ByteArrayBuffer buffer = new ByteArrayBuffer();
        buffer.putRawPublicKey(key); // prepends the certificate type
        s.write(buffer.getCompactData());

        return key.getKeyType();
    }

    @Override
    public KeyFactory getKeyFactoryInstance() {
        throw new UnsupportedOperationException("Private key operations are not supported for certificates.");
    }

    @Override
    public KeyPair generateKeyPair(int keySize) {
        throw new UnsupportedOperationException("Private key operations are not supported for certificates.");
    }

    @Override
    public KeyPairGenerator getKeyPairGenerator() {
        throw new UnsupportedOperationException("Private key operations are not supported for certificates.");
    }
}
