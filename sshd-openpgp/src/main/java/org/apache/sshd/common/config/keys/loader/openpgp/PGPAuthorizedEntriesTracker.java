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
import java.io.StreamCorruptedException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;
import java.util.stream.Collectors;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.FilePasswordProviderManager;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.keyprovider.KeyTypeIndicator;
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
        implements PGPPublicKeyExtractor, FilePasswordProviderManager, PublicKeyEntryResolver {
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

    @Override
    public PublicKey resolve(SessionContext session, String keyType, byte[] keyData)
            throws IOException, GeneralSecurityException {
        if (!PGPPublicKeyEntryDataResolver.PGP_KEY_TYPES.contains(keyType)) {
            return null;
        }

        String fingerprint = PGPPublicKeyEntryDataResolver.encodeKeyFingerprint(keyData);
        if (GenericUtils.isEmpty(fingerprint)) {
            return null;
        }

        Collection<PublicKey> keys;
        try {
            keys = loadMatchingKeyFingerprints(session, Collections.singletonList(fingerprint));
        } catch (PGPException e) {
            throw new InvalidKeyException("Failed (" + e.getClass().getSimpleName() + ")"
                    + " to load key type=" + keyType + " with fingerprint=" + fingerprint
                    + ": " + e.getMessage(), e);
        }

        int numKeys = GenericUtils.size(keys);
        if (numKeys > 1) {
            throw new StreamCorruptedException("Multiple matches (" + numKeys + ")"
                + " for " + keyType + " fingerprint=" + fingerprint);
        }

        return GenericUtils.head(keys);
    }

    public void addWatchedFile(Path p) {
        Objects.requireNonNull(p, "No file provided");
        List<PGPPublicKeyFileWatcher> files = getWatchedFiles();
        files.add(new PGPPublicKeyFileWatcher(p));
    }

    public List<PublicKey> resolveAuthorizedEntries(
            SessionContext session, Collection<? extends PublicKeyEntry> entries, PublicKeyEntryResolver fallbackResolver)
                throws IOException, GeneralSecurityException, PGPException {
        Map<String, ? extends Collection<PublicKeyEntry>> typesMap = KeyTypeIndicator.groupByKeyType(entries);
        if (GenericUtils.isEmpty(typesMap)) {
            return Collections.emptyList();
        }

        List<PublicKey> keys = new ArrayList<>(entries.size());
        for (Map.Entry<String, ? extends Collection<PublicKeyEntry>> te : typesMap.entrySet()) {
            String keyType = te.getKey();
            Collection<PublicKeyEntry> keyEntries = te.getValue();
            Collection<PublicKey> subKeys = PGPPublicKeyEntryDataResolver.PGP_KEY_TYPES.contains(keyType)
                ? loadMatchingAuthorizedEntries(session, keyEntries)
                : PublicKeyEntry.resolvePublicKeyEntries(session, keyEntries, fallbackResolver);
            if (GenericUtils.isEmpty(subKeys)) {
                continue;
            }

            keys.addAll(subKeys);
        }

        return keys;
    }

    public List<PublicKey> loadMatchingAuthorizedEntries(
            SessionContext session, Collection<? extends PublicKeyEntry> entries)
                throws IOException, GeneralSecurityException, PGPException {
        int numEntries = GenericUtils.size(entries);
        if (numEntries <= 0) {
            return Collections.emptyList();
        }

        Collection<String> fingerprints = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        for (PublicKeyEntry pke : entries) {
            String keyType = pke.getKeyType();
            if (GenericUtils.isEmpty(keyType)
                    || (!PGPPublicKeyEntryDataResolver.PGP_KEY_TYPES.contains(keyType))) {
                continue;
            }

            String fp = PGPPublicKeyEntryDataResolver.DEFAULT.encodeEntryKeyData(pke.getKeyData());
            if (GenericUtils.isEmpty(fp)) {
                continue;
            }

            if (!fingerprints.add(fp)) {
                //noinspection UnnecessaryContinue
                continue;   // debug breakpoint
            }
        }

        return loadMatchingKeyFingerprints(session, fingerprints);
    }

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
                continue;   // debug breakpoint
            }

            for (Subkey sk : matches) {
                PublicKey pk;
                try {
                    pk = extractPublicKey(resourceKey, sk);
                    if (pk == null) {
                        continue;   // debug breakpoint
                    }
                } catch (IOException | GeneralSecurityException | RuntimeException e) {
                    log.error("loadMatchingKeyFingerprints({}) failed ({}) to convert {} from {} to public key: {}",
                        session, e.getClass().getSimpleName(), sk, resourceKey, e.getMessage());
                    if (debugEnabled) {
                        log.debug("loadMatchingKeyFingerprints(" + session + ")[" + resourceKey + "][" + sk + "] conversion failure details", e);
                    }
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
