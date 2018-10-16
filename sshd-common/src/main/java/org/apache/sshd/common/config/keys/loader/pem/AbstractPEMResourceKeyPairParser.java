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
package org.apache.sshd.common.config.keys.loader.pem;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StreamCorruptedException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.security.auth.login.CredentialException;
import javax.security.auth.login.FailedLoginException;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.loader.AbstractKeyPairResourceParser;
import org.apache.sshd.common.config.keys.loader.KeyPairResourceParser;
import org.apache.sshd.common.config.keys.loader.PrivateKeyEncryptionContext;
import org.apache.sshd.common.config.keys.loader.PrivateKeyObfuscator;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;

/**
 * Base class for PEM file key-pair loaders
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractPEMResourceKeyPairParser
        extends AbstractKeyPairResourceParser
        implements KeyPairPEMResourceParser {
    private final String algo;
    private final String algId;

    protected AbstractPEMResourceKeyPairParser(String algo, String algId, List<String> beginners, List<String> enders) {
        super(beginners, enders);
        this.algo = ValidateUtils.checkNotNullAndNotEmpty(algo, "No encryption algorithm provided");
        this.algId = ValidateUtils.checkNotNullAndNotEmpty(algId, "No algorithm identifier provided");
    }

    @Override
    public String getAlgorithm() {
        return algo;
    }

    @Override
    public String getAlgorithmIdentifier() {
        return algId;
    }

    @Override
    public Collection<KeyPair> extractKeyPairs(
            String resourceKey, String beginMarker, String endMarker, FilePasswordProvider passwordProvider, List<String> lines)
                    throws IOException, GeneralSecurityException {
        if (GenericUtils.isEmpty(lines)) {
            return Collections.emptyList();
        }

        Boolean encrypted = null;
        byte[] initVector = null;
        String algInfo = null;
        int dataStartIndex = -1;
        for (int index = 0; index < lines.size(); index++) {
            String line = GenericUtils.trimToEmpty(lines.get(index));
            if (GenericUtils.isEmpty(line)) {
                continue;
            }

            // check if header line - if not, assume data lines follow
            int headerPos = line.indexOf(':');
            if (headerPos < 0) {
                dataStartIndex = index;
                break;
            }

            if (line.startsWith("Proc-Type:")) {
                if (encrypted != null) {
                    throw new StreamCorruptedException("Multiple encryption indicators in " + resourceKey);
                }

                line = line.substring(headerPos + 1).trim();
                line = line.toUpperCase();
                encrypted = Boolean.valueOf(line.contains("ENCRYPTED"));
            } else if (line.startsWith("DEK-Info:")) {
                if ((initVector != null) || (algInfo != null)) {
                    throw new StreamCorruptedException("Multiple encryption settings in " + resourceKey);
                }

                line = line.substring(headerPos + 1).trim();
                headerPos = line.indexOf(',');
                if (headerPos < 0) {
                    throw new StreamCorruptedException(resourceKey + ": Missing encryption data values separator in line '" + line + "'");
                }

                algInfo = line.substring(0, headerPos).trim();

                String algInitVector = line.substring(headerPos + 1).trim();
                initVector = BufferUtils.decodeHex(BufferUtils.EMPTY_HEX_SEPARATOR, algInitVector);
            }
        }

        if (dataStartIndex < 0) {
            throw new StreamCorruptedException("No data lines (only headers or empty) found in " + resourceKey);
        }

        List<String> dataLines = lines.subList(dataStartIndex, lines.size());
        if ((encrypted != null) || (algInfo != null) || (initVector != null)) {
            if (passwordProvider == null) {
                throw new CredentialException("Missing password provider for encrypted resource=" + resourceKey);
            }

            String password = passwordProvider.getPassword(resourceKey);
            if (GenericUtils.isEmpty(password)) {
                throw new FailedLoginException("No password data for encrypted resource=" + resourceKey);
            }

            PrivateKeyEncryptionContext encContext = new PrivateKeyEncryptionContext(algInfo);
            encContext.setPassword(password);
            encContext.setInitVector(initVector);
            byte[] encryptedData = KeyPairResourceParser.extractDataBytes(dataLines);
            byte[] decodedData = applyPrivateKeyCipher(encryptedData, encContext, false);
            try (InputStream bais = new ByteArrayInputStream(decodedData)) {
                return extractKeyPairs(resourceKey, beginMarker, endMarker, passwordProvider, bais);
            }
        }

        return super.extractKeyPairs(resourceKey, beginMarker, endMarker, passwordProvider, dataLines);
    }

    protected byte[] applyPrivateKeyCipher(byte[] bytes, PrivateKeyEncryptionContext encContext, boolean encryptIt) throws GeneralSecurityException {
        String cipherName = encContext.getCipherName();
        PrivateKeyObfuscator o = encContext.resolvePrivateKeyObfuscator();
        if (o == null) {
            throw new NoSuchAlgorithmException("decryptPrivateKeyData(" + encContext + ")[encrypt=" + encryptIt + "] unknown cipher: " + cipherName);
        }

        if (encryptIt) {
            byte[]  initVector = encContext.getInitVector();
            if (GenericUtils.isEmpty(initVector)) {
                initVector = o.generateInitializationVector(encContext);
                encContext.setInitVector(initVector);
            }
        }

        return o.applyPrivateKeyCipher(bytes, encContext, encryptIt);
    }
}
