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
import java.net.ProtocolException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.security.auth.login.CredentialException;
import javax.security.auth.login.FailedLoginException;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.FilePasswordProvider.ResourceDecodeResult;
import org.apache.sshd.common.config.keys.loader.AbstractKeyPairResourceParser;
import org.apache.sshd.common.config.keys.loader.KeyPairResourceParser;
import org.apache.sshd.common.config.keys.loader.PrivateKeyEncryptionContext;
import org.apache.sshd.common.config.keys.loader.PrivateKeyObfuscator;
import org.apache.sshd.common.session.SessionContext;
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

    protected AbstractPEMResourceKeyPairParser(
                                               String algo, String algId, List<String> beginners, List<String> enders) {
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
            SessionContext session, NamedResource resourceKey,
            String beginMarker, String endMarker,
            FilePasswordProvider passwordProvider,
            List<String> lines, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        if (GenericUtils.isEmpty(lines)) {
            return Collections.emptyList();
        }

        Boolean encrypted = null;
        byte[] initVector = null;
        String algInfo = null;
        int dataStartIndex = -1;
        boolean hdrsAvailable = GenericUtils.isNotEmpty(headers);
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

            String hdrName = line.substring(0, headerPos).trim();
            String hdrValue = line.substring(headerPos + 1).trim();
            if (!hdrsAvailable) {
                Map<String, String> accHeaders = GenericUtils.isEmpty(headers)
                        ? new TreeMap<>(String.CASE_INSENSITIVE_ORDER)
                        : headers;
                accHeaders.put(hdrName, hdrValue);
            }

            if (hdrName.equalsIgnoreCase("Proc-Type")) {
                if (encrypted != null) {
                    throw new StreamCorruptedException("Multiple encryption indicators in " + resourceKey);
                }

                hdrValue = hdrValue.toUpperCase();
                encrypted = Boolean.valueOf(line.contains("ENCRYPTED"));
            } else if (hdrName.equalsIgnoreCase("DEK-Info")) {
                if ((initVector != null) || (algInfo != null)) {
                    throw new StreamCorruptedException("Multiple encryption settings in " + resourceKey);
                }

                int infoPos = hdrValue.indexOf(',');
                if (infoPos < 0) {
                    throw new StreamCorruptedException(
                            resourceKey + ": Missing encryption data values separator in line '" + line + "'");
                }

                algInfo = hdrValue.substring(0, infoPos).trim();

                String algInitVector = hdrValue.substring(infoPos + 1).trim();
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

            for (int retryIndex = 0;; retryIndex++) {
                String password = passwordProvider.getPassword(session, resourceKey, retryIndex);
                Collection<KeyPair> keys;
                try {
                    if (GenericUtils.isEmpty(password)) {
                        throw new FailedLoginException("No password data for encrypted resource=" + resourceKey);
                    }

                    PrivateKeyEncryptionContext encContext = new PrivateKeyEncryptionContext(algInfo);
                    encContext.setPassword(password);
                    encContext.setInitVector(initVector);

                    byte[] encryptedData = GenericUtils.EMPTY_BYTE_ARRAY;
                    byte[] decodedData = GenericUtils.EMPTY_BYTE_ARRAY;
                    try {
                        encryptedData = KeyPairResourceParser.extractDataBytes(dataLines);
                        decodedData = applyPrivateKeyCipher(encryptedData, encContext, false);
                        try (InputStream bais = new ByteArrayInputStream(decodedData)) {
                            keys = extractKeyPairs(session, resourceKey, beginMarker, endMarker, passwordProvider, bais,
                                    headers);
                        }
                    } finally {
                        Arrays.fill(encryptedData, (byte) 0); // get rid of sensitive data a.s.a.p.
                        Arrays.fill(decodedData, (byte) 0); // get rid of sensitive data a.s.a.p.
                    }
                } catch (IOException | GeneralSecurityException | RuntimeException e) {
                    ResourceDecodeResult result
                            = passwordProvider.handleDecodeAttemptResult(session, resourceKey, retryIndex, password, e);
                    password = null; // get rid of sensitive data a.s.a.p.
                    if (result == null) {
                        result = ResourceDecodeResult.TERMINATE;
                    }

                    switch (result) {
                        case TERMINATE:
                            throw e;
                        case RETRY:
                            continue;
                        case IGNORE:
                            return Collections.emptyList();
                        default:
                            throw new ProtocolException(
                                    "Unsupported decode attempt result (" + result + ") for " + resourceKey);
                    }
                }

                passwordProvider.handleDecodeAttemptResult(session, resourceKey, retryIndex, password, null);
                password = null; // get rid of sensitive data a.s.a.p.
                return keys;
            }
        }

        return super.extractKeyPairs(session, resourceKey, beginMarker, endMarker, passwordProvider, dataLines, headers);
    }

    protected byte[] applyPrivateKeyCipher(
            byte[] bytes, PrivateKeyEncryptionContext encContext, boolean encryptIt)
            throws GeneralSecurityException, IOException {
        String cipherName = encContext.getCipherName();
        PrivateKeyObfuscator o = encContext.resolvePrivateKeyObfuscator();
        if (o == null) {
            throw new NoSuchAlgorithmException(
                    "decryptPrivateKeyData(" + encContext + ")[encrypt=" + encryptIt + "] unknown cipher: " + cipherName);
        }

        if (encryptIt) {
            byte[] initVector = encContext.getInitVector();
            if (GenericUtils.isEmpty(initVector)) {
                initVector = o.generateInitializationVector(encContext);
                encContext.setInitVector(initVector);
            }
        }

        return o.applyPrivateKeyCipher(bytes, encContext, encryptIt);
    }
}
