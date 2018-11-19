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

package org.apache.sshd.common.config.keys.loader.openpgp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.sshd.common.config.keys.impl.AbstractPublicKeyEntryDecoder;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.io.IoUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class PGPPublicKeyEntryDecoder extends AbstractPublicKeyEntryDecoder<PublicKey, PrivateKey> {
    public PGPPublicKeyEntryDecoder() {
        super(PublicKey.class, PrivateKey.class, PGPPublicKeyEntryDataResolver.PGP_KEY_TYPES);
    }

    @Override
    public PublicKey decodePublicKeyByType(String keyType, InputStream keyData)
            throws IOException, GeneralSecurityException {
        return decodePublicKey(keyType, keyData);
    }

    @Override
    public PublicKey decodePublicKey(String keyType, InputStream keyData)
            throws IOException, GeneralSecurityException {
        return decodePublicKey(keyType, IoUtils.toByteArray(keyData));
    }

    @Override
    public PublicKey decodePublicKey(String keyType, byte[] keyData, int offset, int length)
            throws IOException, GeneralSecurityException {
        String fingerprint = BufferUtils.toHex(keyData, offset, length, BufferUtils.EMPTY_HEX_SEPARATOR).toString();
        throw new KeyException("TODO decode key type=" + keyType + " for fingerprint=" + fingerprint);
    }

    @Override
    public String encodePublicKey(OutputStream s, PublicKey key) throws IOException {
        throw new UnsupportedOperationException("N/A");
    }

    @Override
    public PublicKey clonePublicKey(PublicKey key) throws GeneralSecurityException {
        throw new UnsupportedOperationException("N/A");
    }

    @Override
    public PrivateKey clonePrivateKey(PrivateKey key) throws GeneralSecurityException {
        throw new UnsupportedOperationException("N/A");
    }

    @Override
    public KeyPairGenerator getKeyPairGenerator() throws GeneralSecurityException {
        throw new UnsupportedOperationException("N/A");
    }

    @Override
    public KeyFactory getKeyFactoryInstance() throws GeneralSecurityException {
        throw new UnsupportedOperationException("N/A");
    }
}
