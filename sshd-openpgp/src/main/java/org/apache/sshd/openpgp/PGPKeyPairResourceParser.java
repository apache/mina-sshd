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

package org.apache.sshd.openpgp;

import java.io.IOException;
import java.io.InputStream;
import java.io.StreamCorruptedException;
import java.net.ProtocolException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.FilePasswordProvider.ResourceDecodeResult;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.loader.AbstractKeyPairResourceParser;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.bouncycastle.openpgp.PGPException;
import org.c02e.jpgpj.Key;
import org.c02e.jpgpj.Subkey;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class PGPKeyPairResourceParser
        extends AbstractKeyPairResourceParser
        implements PGPKeyLoader,
        PGPPublicKeyExtractor,
        PGPPrivateKeyExtractor {
    public static final String BEGIN_MARKER = "BEGIN PGP PRIVATE KEY BLOCK";
    public static final List<String> BEGINNERS = Collections.unmodifiableList(Collections.singletonList(BEGIN_MARKER));

    public static final String END_MARKER = "END PGP PRIVATE KEY BLOCK";
    public static final List<String> ENDERS = Collections.unmodifiableList(Collections.singletonList(END_MARKER));

    public static final PGPKeyPairResourceParser INSTANCE = new PGPKeyPairResourceParser();

    public PGPKeyPairResourceParser() {
        super(BEGINNERS, ENDERS);
    }

    @Override
    public Collection<KeyPair> extractKeyPairs(
            SessionContext session, NamedResource resourceKey,
            String beginMarker, String endMarker,
            FilePasswordProvider passwordProvider,
            List<String> lines, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        // We need to re-construct the original data - including start/end markers
        String eol = System.lineSeparator();
        int numLines = GenericUtils.size(lines);
        StringBuilder sb = new StringBuilder(
                beginMarker.length() + endMarker.length() + 4 + numLines * 80)
                        .append(beginMarker);
        if (numLines > 0) {
            for (String l : lines) {
                sb.append(eol).append(l);
            }
        }
        sb.append(eol).append(endMarker).append(eol);

        String keyData = sb.toString();
        byte[] dataBytes = keyData.getBytes(StandardCharsets.US_ASCII);
        try {
            return extractKeyPairs(session, resourceKey, beginMarker, endMarker, passwordProvider, dataBytes, headers);
        } finally {
            Arrays.fill(dataBytes, (byte) 0); // clean up sensitive data a.s.a.p.
        }
    }

    @Override
    public Collection<KeyPair> extractKeyPairs(
            SessionContext session, NamedResource resourceKey,
            String beginMarker, String endMarker,
            FilePasswordProvider passwordProvider,
            InputStream stream, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        for (int retryCount = 0;; retryCount++) {
            String password = (passwordProvider == null)
                    ? null
                    : passwordProvider.getPassword(session, resourceKey, retryCount);
            Collection<KeyPair> keys;
            try {
                if (retryCount > 0) {
                    stream.reset();
                }

                Key key = PGPKeyLoader.loadPGPKey(stream, password);
                keys = extractKeyPairs(resourceKey, key.getSubkeys());
                key = null; // get rid of sensitive data a.s.a.p.
            } catch (IOException | GeneralSecurityException | PGPException | RuntimeException e) {
                ResourceDecodeResult result = (passwordProvider != null)
                        ? passwordProvider.handleDecodeAttemptResult(session, resourceKey, retryCount, password, e)
                        : ResourceDecodeResult.TERMINATE;
                password = null; // get rid of sensitive data a.s.a.p.
                if (result == null) {
                    result = ResourceDecodeResult.TERMINATE;
                }

                switch (result) {
                    case TERMINATE:
                        if (e instanceof PGPException) {
                            throw new StreamCorruptedException(
                                    "Failed (" + e.getClass().getSimpleName() + ")"
                                                               + " to decode " + resourceKey + ": " + e.getMessage());
                        } else if (e instanceof IOException) {
                            throw (IOException) e;
                        } else if (e instanceof GeneralSecurityException) {
                            throw (GeneralSecurityException) e;
                        } else {
                            throw (RuntimeException) e;
                        }
                    case RETRY:
                        continue;
                    case IGNORE:
                        return Collections.emptyList();
                    default:
                        throw new ProtocolException("Unsupported decode attempt result (" + result + ") for " + resourceKey);
                }
            }

            if (passwordProvider != null) {
                passwordProvider.handleDecodeAttemptResult(session, resourceKey, retryCount, password, null);
                password = null; // get rid of sensitive data a.s.a.p.
            }

            return keys;
        }
    }

    public List<KeyPair> extractKeyPairs(NamedResource resourceKey, Collection<? extends Subkey> subKeys)
            throws IOException, GeneralSecurityException {
        if (GenericUtils.isEmpty(subKeys)) {
            return Collections.emptyList();
        }

        List<KeyPair> kpList = new ArrayList<>(subKeys.size());
        boolean debugEnabled = log.isDebugEnabled();
        for (Subkey sk : subKeys) {
            PublicKey pubKey;
            try {
                pubKey = extractPublicKey(resourceKey, sk);
                if (pubKey == null) {
                    if (debugEnabled) {
                        log.debug("extractKeyPairs({}) no public key extracted from {}", resourceKey, sk);
                    }
                    continue;
                }
            } catch (IOException | GeneralSecurityException | RuntimeException | Error e) {
                log.error("extractKeyPairs({}) failed ({}) to extract public key of {}: {}",
                        resourceKey, e.getClass().getSimpleName(), sk, e.getMessage());
                throw e;
            }

            PrivateKey prvKey;
            try {
                prvKey = extractPrivateKey(resourceKey, sk, pubKey);
                if (prvKey == null) {
                    if (debugEnabled) {
                        log.debug("extractKeyPairs({}) no private key extracted from {}", resourceKey, sk);
                    }
                    continue;
                }
            } catch (IOException | GeneralSecurityException | RuntimeException | Error e) {
                log.error("extractKeyPairs({}) failed ({}) to extract private key of {}: {}",
                        resourceKey, e.getClass().getSimpleName(), sk, e.getMessage());
                throw e;
            } catch (PGPException e) {
                log.error("extractKeyPairs({}) failed ({}) to parse private key of {}: {}",
                        resourceKey, e.getClass().getSimpleName(), sk, e.getMessage());
                throw new StreamCorruptedException("Failed to parse " + resourceKey + " sub-key=" + sk + ": " + e.getMessage());
            }

            KeyPair kp = new KeyPair(pubKey, prvKey);
            KeyPair prev = kpList.isEmpty()
                    ? null
                    : kpList.stream()
                            .filter(e -> KeyUtils.compareKeyPairs(e, kp))
                            .findFirst()
                            .orElse(null);
            if (prev != null) {
                if (debugEnabled) {
                    log.debug("extractKeyPairs({}) skip duplicate sub-key={}", resourceKey, sk);
                }
                continue;
            }

            kpList.add(kp);
        }

        return kpList;
    }

    @Override
    public <K extends PublicKey> K generatePublicKey(String algorithm, Class<K> keyType, KeySpec keySpec)
            throws GeneralSecurityException {
        KeyFactory factory = getKeyFactory(algorithm);
        PublicKey pubKey = factory.generatePublic(keySpec);
        return keyType.cast(pubKey);
    }

    @Override
    public <K extends PrivateKey> K generatePrivateKey(String algorithm, Class<K> keyType, KeySpec keySpec)
            throws GeneralSecurityException {
        KeyFactory factory = getKeyFactory(algorithm);
        PrivateKey prvKey = factory.generatePrivate(keySpec);
        return keyType.cast(prvKey);
    }

    protected KeyFactory getKeyFactory(String algorithm) throws GeneralSecurityException {
        return SecurityUtils.getKeyFactory(algorithm);
    }
}
