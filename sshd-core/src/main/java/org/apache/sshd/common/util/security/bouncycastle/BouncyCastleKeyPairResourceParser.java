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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.loader.AbstractKeyPairResourceParser;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.security.SecurityProviderRegistrar;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BouncyCastleKeyPairResourceParser extends AbstractKeyPairResourceParser {
    public static final List<String> BEGINNERS =
            Collections.unmodifiableList(
                    Arrays.asList(
                            "BEGIN RSA PRIVATE KEY",
                            "BEGIN DSA PRIVATE KEY",
                            "BEGIN EC PRIVATE KEY"));

    public static final List<String> ENDERS =
            Collections.unmodifiableList(
                    Arrays.asList(
                            "END RSA PRIVATE KEY",
                            "END DSA PRIVATE KEY",
                            "END EC PRIVATE KEY"));

    public static final BouncyCastleKeyPairResourceParser INSTANCE = new BouncyCastleKeyPairResourceParser();

    public BouncyCastleKeyPairResourceParser() {
        super(BEGINNERS, ENDERS);
    }

    @Override
    public Collection<KeyPair> extractKeyPairs(
            String resourceKey, String beginMarker, String endMarker, FilePasswordProvider passwordProvider, List<String> lines)
                    throws IOException, GeneralSecurityException {
        StringBuilder writer = new StringBuilder(beginMarker.length() + endMarker.length() + lines.size() * 80);
        writer.append(beginMarker).append(IoUtils.EOL);
        lines.forEach(l -> writer.append(l).append(IoUtils.EOL));
        writer.append(endMarker).append(IoUtils.EOL);

        String data = writer.toString();
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        try (InputStream bais = new ByteArrayInputStream(dataBytes)) {
            return extractKeyPairs(resourceKey, beginMarker, endMarker, passwordProvider, bais);
        }
    }

    @Override
    public Collection<KeyPair> extractKeyPairs(
            String resourceKey, String beginMarker, String endMarker, FilePasswordProvider passwordProvider, InputStream stream)
                    throws IOException, GeneralSecurityException {
        KeyPair kp = loadKeyPair(resourceKey, stream, passwordProvider);
        return (kp == null) ? Collections.emptyList() : Collections.singletonList(kp);
    }

    public static KeyPair loadKeyPair(String resourceKey, InputStream inputStream, FilePasswordProvider provider)
            throws IOException, GeneralSecurityException {
        try (PEMParser r = new PEMParser(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            Object o = r.readObject();

            SecurityProviderRegistrar registrar = SecurityUtils.getRegisteredProvider(SecurityUtils.BOUNCY_CASTLE);
            if (registrar == null) {
                throw new NoSuchProviderException(SecurityUtils.BOUNCY_CASTLE + " registrar not available");
            }

            JcaPEMKeyConverter pemConverter = new JcaPEMKeyConverter();
            if (registrar.isNamedProviderUsed()) {
                pemConverter.setProvider(registrar.getName());
            } else {
                pemConverter.setProvider(registrar.getSecurityProvider());
            }
            if (o instanceof PEMEncryptedKeyPair) {
                ValidateUtils.checkNotNull(provider, "No password provider for resource=%s", resourceKey);

                String password = ValidateUtils.checkNotNullAndNotEmpty(provider.getPassword(resourceKey), "No password provided for resource=%s", resourceKey);
                JcePEMDecryptorProviderBuilder decryptorBuilder = new JcePEMDecryptorProviderBuilder();
                PEMDecryptorProvider pemDecryptor = decryptorBuilder.build(password.toCharArray());
                o = ((PEMEncryptedKeyPair) o).decryptKeyPair(pemDecryptor);
            }

            if (o instanceof PEMKeyPair) {
                return pemConverter.getKeyPair((PEMKeyPair) o);
            } else if (o instanceof KeyPair) {
                return (KeyPair) o;
            } else {
                throw new IOException("Failed to read " + resourceKey + " - unknown result object: " + o);
            }
        }
    }
}
