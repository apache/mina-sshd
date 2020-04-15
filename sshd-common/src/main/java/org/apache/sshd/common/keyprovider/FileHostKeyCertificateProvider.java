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
package org.apache.sshd.common.keyprovider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.StreamSupport;

import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

public class FileHostKeyCertificateProvider extends AbstractLoggingBean implements HostKeyCertificateProvider {
    private Collection<? extends Path> files;

    public FileHostKeyCertificateProvider() {
        super();
    }

    public FileHostKeyCertificateProvider(Path path) {
        this(Collections.singletonList(Objects.requireNonNull(path, "No path provided")));
    }

    public FileHostKeyCertificateProvider(Path... files) {
        this(Arrays.asList(ValidateUtils.checkNotNullAndNotEmpty(files, "No path provided")));
    }

    public FileHostKeyCertificateProvider(Collection<? extends Path> files) {
        this.files = files;
    }

    public Collection<? extends Path> getPaths() {
        return files;
    }

    @Override
    public Iterable<OpenSshCertificate> loadCertificates(SessionContext session) throws IOException, GeneralSecurityException {

        List<OpenSshCertificate> certificates = new ArrayList<>();
        for (Path file : files) {
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            for (String line : lines) {
                line = GenericUtils.replaceWhitespaceAndTrim(line);
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }

                PublicKeyEntry publicKeyEntry = PublicKeyEntry.parsePublicKeyEntry(line);
                if (publicKeyEntry == null) {
                    continue;
                }
                PublicKey publicKey = publicKeyEntry.resolvePublicKey(session, null, null);
                if (publicKey == null) {
                    continue;
                }
                if (!(publicKey instanceof OpenSshCertificate)) {
                    throw new InvalidKeyException("Got unexpected key type in " + file + ". Expected OpenSSHCertificate.");
                }
                certificates.add((OpenSshCertificate) publicKey);
            }
        }

        return certificates;
    }

    @Override
    public OpenSshCertificate loadCertificate(SessionContext session, String keyType) throws IOException, GeneralSecurityException {
        return StreamSupport.stream(loadCertificates(session).spliterator(), false)
            .filter(pubKey -> Objects.equals(pubKey.getKeyType(), keyType))
            .findFirst().orElse(null);
    }
}
