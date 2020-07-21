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

package org.apache.sshd.putty;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StreamCorruptedException;
import java.net.ProtocolException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.security.auth.login.FailedLoginException;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.FilePasswordProvider.ResourceDecodeResult;
import org.apache.sshd.common.config.keys.impl.AbstractIdentityResourceLoader;
import org.apache.sshd.common.config.keys.loader.KeyPairResourceParser;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @param  <PUB> Generic public key type
 * @param  <PRV> Generic private key type
 * @author       <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractPuttyKeyDecoder<PUB extends PublicKey, PRV extends PrivateKey>
        extends AbstractIdentityResourceLoader<PUB, PRV>
        implements PuttyKeyPairResourceParser<PUB, PRV> {
    public static final String ENCRYPTION_HEADER = "Encryption";

    protected AbstractPuttyKeyDecoder(Class<PUB> pubType, Class<PRV> prvType, Collection<String> names) {
        super(pubType, prvType, names);
    }

    @Override
    public boolean canExtractKeyPairs(NamedResource resourceKey, List<String> lines)
            throws IOException, GeneralSecurityException {
        if (!PuttyKeyPairResourceParser.super.canExtractKeyPairs(resourceKey, lines)) {
            return false;
        }

        for (String l : lines) {
            l = GenericUtils.trimToEmpty(l);
            if (!l.startsWith(KEY_FILE_HEADER_PREFIX)) {
                continue;
            }

            int pos = l.indexOf(':');
            if ((pos <= 0) || (pos >= (l.length() - 1))) {
                return false;
            }

            Collection<String> supported = getSupportedKeyTypes();
            String typeValue = l.substring(pos + 1).trim();
            return supported.contains(typeValue);
        }

        return false;
    }

    @Override
    public Collection<KeyPair> loadKeyPairs(
            SessionContext session, NamedResource resourceKey, FilePasswordProvider passwordProvider, List<String> lines)
            throws IOException, GeneralSecurityException {
        List<String> pubLines = Collections.emptyList();
        List<String> prvLines = Collections.emptyList();
        Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        String prvEncryption = null;
        for (int index = 0, numLines = lines.size(); index < numLines; index++) {
            String l = lines.get(index);
            l = GenericUtils.trimToEmpty(l);
            int pos = l.indexOf(':');
            if ((pos <= 0) || (pos >= (l.length() - 1))) {
                continue;
            }

            String hdrName = l.substring(0, pos).trim();
            String hdrValue = l.substring(pos + 1).trim();
            headers.put(hdrName, hdrValue);
            switch (hdrName) {
                case ENCRYPTION_HEADER:
                    if (prvEncryption != null) {
                        throw new StreamCorruptedException("Duplicate " + hdrName + " in" + resourceKey);
                    }
                    prvEncryption = hdrValue;
                    break;
                case PUBLIC_LINES_HEADER:
                    pubLines = extractDataLines(resourceKey, lines, index + 1, hdrName, hdrValue, pubLines);
                    index += pubLines.size();
                    break;
                case PRIVATE_LINES_HEADER:
                    prvLines = extractDataLines(resourceKey, lines, index + 1, hdrName, hdrValue, prvLines);
                    index += prvLines.size();
                    break;
                default: // ignored
            }
        }

        return loadKeyPairs(session, resourceKey, pubLines, prvLines, prvEncryption, passwordProvider, headers);
    }

    public static List<String> extractDataLines(
            NamedResource resourceKey, List<String> lines, int startIndex, String hdrName, String hdrValue,
            List<String> curLines)
            throws IOException {
        if (GenericUtils.size(curLines) > 0) {
            throw new StreamCorruptedException("Duplicate " + hdrName + " in " + resourceKey);
        }

        int numLines;
        try {
            numLines = Integer.parseInt(hdrValue);
        } catch (NumberFormatException e) {
            throw new StreamCorruptedException("Bad " + hdrName + " value (" + hdrValue + ") in " + resourceKey);
        }

        int endIndex = startIndex + numLines;
        int totalLines = lines.size();
        if (endIndex > totalLines) {
            throw new StreamCorruptedException("Excessive " + hdrName + " value (" + hdrValue + ") in " + resourceKey);
        }

        return lines.subList(startIndex, endIndex);
    }

    public Collection<KeyPair> loadKeyPairs(
            SessionContext session, NamedResource resourceKey,
            List<String> pubLines, List<String> prvLines, String prvEncryption,
            FilePasswordProvider passwordProvider, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        return loadKeyPairs(session, resourceKey,
                KeyPairResourceParser.joinDataLines(pubLines), KeyPairResourceParser.joinDataLines(prvLines),
                prvEncryption, passwordProvider, headers);
    }

    public Collection<KeyPair> loadKeyPairs(
            SessionContext session, NamedResource resourceKey,
            String pubData, String prvData, String prvEncryption,
            FilePasswordProvider passwordProvider, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        byte[] pubBytes = GenericUtils.EMPTY_BYTE_ARRAY;
        byte[] prvBytes = GenericUtils.EMPTY_BYTE_ARRAY;
        try {
            Decoder b64Decoder = Base64.getDecoder();
            pubBytes = b64Decoder.decode(pubData);
            prvBytes = b64Decoder.decode(prvData);
            if (GenericUtils.isEmpty(prvEncryption)
                    || NO_PRIVATE_KEY_ENCRYPTION_VALUE.equalsIgnoreCase(prvEncryption)) {
                return loadKeyPairs(resourceKey, pubBytes, prvBytes, headers);
            }

            // format is "<cipher><bits>-<mode>" - e.g., "aes256-cbc"
            int pos = prvEncryption.indexOf('-');
            if (pos <= 0) {
                throw new StreamCorruptedException("Missing private key encryption mode in " + prvEncryption);
            }

            String mode = prvEncryption.substring(pos + 1).toUpperCase();
            String algName = null;
            int numBits = 0;
            for (int index = 0; index < pos; index++) {
                char ch = prvEncryption.charAt(index);
                if ((ch >= '0') && (ch <= '9')) {
                    algName = prvEncryption.substring(0, index).toUpperCase();
                    numBits = Integer.parseInt(prvEncryption.substring(index, pos));
                    break;
                }
            }

            if (GenericUtils.isEmpty(algName) || (numBits <= 0)) {
                throw new StreamCorruptedException("Missing private key encryption algorithm details in " + prvEncryption);
            }

            for (int retryIndex = 0;; retryIndex++) {
                String password = passwordProvider.getPassword(session, resourceKey, retryIndex);

                Collection<KeyPair> keys;
                try {
                    if (GenericUtils.isEmpty(password)) {
                        throw new FailedLoginException("No password data for encrypted resource=" + resourceKey);
                    }

                    byte[] decBytes = PuttyKeyPairResourceParser.decodePrivateKeyBytes(
                            prvBytes, algName, numBits, mode, password);
                    try {
                        keys = loadKeyPairs(resourceKey, pubBytes, decBytes, headers);
                    } finally {
                        Arrays.fill(decBytes, (byte) 0); // eliminate sensitive data a.s.a.p.
                    }
                } catch (IOException | GeneralSecurityException | RuntimeException e) {
                    ResourceDecodeResult result
                            = passwordProvider.handleDecodeAttemptResult(session, resourceKey, retryIndex, password, e);
                    password = null; // get rid of sensitive data a.s.a.p.
                    if (result == null) {
                        result = ResourceDecodeResult.TERMINATE;
                    }

                    password = null; // GC hint - don't keep sensitive data in memory longer than necessary
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
        } finally {
            Arrays.fill(pubBytes, (byte) 0); // eliminate sensitive data a.s.a.p.
            Arrays.fill(prvBytes, (byte) 0); // eliminate sensitive data a.s.a.p.
        }
    }

    public Collection<KeyPair> loadKeyPairs(
            NamedResource resourceKey, byte[] pubData, byte[] prvData, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        ValidateUtils.checkNotNullAndNotEmpty(pubData, "No public key data in %s", resourceKey);
        ValidateUtils.checkNotNullAndNotEmpty(prvData, "No private key data in %s", resourceKey);
        try (InputStream pubStream = new ByteArrayInputStream(pubData);
             InputStream prvStream = new ByteArrayInputStream(prvData)) {
            return loadKeyPairs(resourceKey, pubStream, prvStream, headers);
        }
    }

    public Collection<KeyPair> loadKeyPairs(
            NamedResource resourceKey, InputStream pubData, InputStream prvData, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        try (PuttyKeyReader pubReader
                = new PuttyKeyReader(ValidateUtils.checkNotNull(pubData, "No public key data in %s", resourceKey));
             PuttyKeyReader prvReader
                     = new PuttyKeyReader(ValidateUtils.checkNotNull(prvData, "No private key data in %s", resourceKey))) {
            return loadKeyPairs(resourceKey, pubReader, prvReader, headers);
        }
    }

    public abstract Collection<KeyPair> loadKeyPairs(
            NamedResource resourceKey, PuttyKeyReader pubReader, PuttyKeyReader prvReader, Map<String, String> headers)
            throws IOException, GeneralSecurityException;
}
