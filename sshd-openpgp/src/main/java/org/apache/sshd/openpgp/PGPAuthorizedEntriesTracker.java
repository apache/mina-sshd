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
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.FilePasswordProviderManager;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.bouncycastle.openpgp.PGPException;
import org.c02e.jpgpj.Key;
import org.c02e.jpgpj.Subkey;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class PGPAuthorizedEntriesTracker
        extends AbstractLoggingBean
        implements PGPAuthorizedKeyEntriesLoader,
        FilePasswordProviderManager {
    private FilePasswordProvider filePasswordProvider;
    private final List<PGPPublicKeyFileWatcher> keyFiles;

    public PGPAuthorizedEntriesTracker() {
        this(Collections.emptyList());
    }

    public PGPAuthorizedEntriesTracker(Path path) {
        this(path, null);
    }

    public PGPAuthorizedEntriesTracker(Path path, FilePasswordProvider passwordProvider) {
        this(Collections.singletonList(Objects.requireNonNull(path, "No path provided")), passwordProvider);
    }

    public PGPAuthorizedEntriesTracker(Collection<? extends Path> keys) {
        this(keys, null);
    }

    public PGPAuthorizedEntriesTracker(Collection<? extends Path> keys, FilePasswordProvider passwordProvider) {
        this.keyFiles = GenericUtils.isEmpty(keys)
                ? new ArrayList<>()
                : keys.stream()
                        .map(k -> new PGPPublicKeyFileWatcher(k))
                        .collect(Collectors.toCollection(() -> new ArrayList<>(keys.size())));
    }

    @Override
    public FilePasswordProvider getFilePasswordProvider() {
        return filePasswordProvider;
    }

    @Override
    public void setFilePasswordProvider(FilePasswordProvider filePasswordProvider) {
        this.filePasswordProvider = filePasswordProvider;
    }

    public List<PGPPublicKeyFileWatcher> getWatchedFiles() {
        return keyFiles;
    }

    public void addWatchedFile(Path p) {
        Objects.requireNonNull(p, "No file provided");
        List<PGPPublicKeyFileWatcher> files = getWatchedFiles();
        files.add(new PGPPublicKeyFileWatcher(p));
    }

    @Override
    public List<PublicKey> loadMatchingKeyFingerprints(
            SessionContext session, Collection<String> fingerprints)
            throws IOException, GeneralSecurityException, PGPException {
        int numEntries = GenericUtils.size(fingerprints);
        if (numEntries <= 0) {
            return Collections.emptyList();
        }

        Collection<PGPPublicKeyFileWatcher> files = getWatchedFiles();
        int numFiles = GenericUtils.size(files);
        if (numFiles <= 0) {
            return Collections.emptyList();
        }

        List<PublicKey> keys = new ArrayList<>(Math.min(numEntries, numFiles));
        FilePasswordProvider provider = getFilePasswordProvider();
        boolean debugEnabled = log.isDebugEnabled();
        for (PGPPublicKeyFileWatcher f : files) {
            PathResource resourceKey = f.toPathResource();
            Key container = f.loadPublicKey(session, resourceKey, provider);
            Map<String, Subkey> fpMap = PGPUtils.mapSubKeysByFingerprint(container);
            int numSubKeys = GenericUtils.size(fpMap);
            Collection<Subkey> matches = (numSubKeys <= 0)
                    ? Collections.emptyList()
                    : fpMap.entrySet()
                            .stream()
                            .filter(e -> fingerprints.contains(e.getKey()))
                            .map(Map.Entry::getValue)
                            .collect(Collectors.toCollection(() -> new ArrayList<>(numSubKeys)));
            int numMatches = GenericUtils.size(matches);
            if (debugEnabled) {
                log.debug("loadMatchingKeyFingerprints({}) found {}/{} matches in {}",
                        session, numMatches, numEntries, resourceKey);
            }
            if (numMatches <= 0) {
                continue; // debug breakpoint
            }

            for (Subkey sk : matches) {
                PublicKey pk;
                try {
                    pk = extractPublicKey(resourceKey, sk);
                    if (pk == null) {
                        continue; // debug breakpoint
                    }
                } catch (IOException | GeneralSecurityException | RuntimeException e) {
                    error("loadMatchingKeyFingerprints({}) failed ({}) to convert {} from {} to public key: {}",
                            session, e.getClass().getSimpleName(), sk, resourceKey, e.getMessage(), e);
                    throw e;
                }

                if (debugEnabled) {
                    log.debug("loadMatchingKeyFingerprints({}) loaded key={}, fingerprint={}, hash={} from {}",
                            session, KeyUtils.getKeyType(pk), sk.getFingerprint(), KeyUtils.getFingerPrint(pk), resourceKey);
                }
                keys.add(pk);
            }
        }

        return keys;
    }

    @Override
    public <K extends PublicKey> K generatePublicKey(String algorithm, Class<K> keyType, KeySpec keySpec)
            throws GeneralSecurityException {
        KeyFactory factory = getKeyFactory(algorithm);
        PublicKey pubKey = factory.generatePublic(keySpec);
        return keyType.cast(pubKey);
    }

    protected KeyFactory getKeyFactory(String algorithm) throws GeneralSecurityException {
        return SecurityUtils.getKeyFactory(algorithm);
    }
}
