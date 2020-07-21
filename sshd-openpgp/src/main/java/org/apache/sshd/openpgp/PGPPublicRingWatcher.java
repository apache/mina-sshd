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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.ModifiableFileWatcher;
import org.apache.sshd.common.util.io.resource.IoResource;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.bouncycastle.openpgp.PGPException;
import org.c02e.jpgpj.Key;
import org.c02e.jpgpj.Ring;
import org.c02e.jpgpj.Subkey;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class PGPPublicRingWatcher extends ModifiableFileWatcher implements PGPAuthorizedKeyEntriesLoader {
    /**
     * @see <A HREF="https://www.gnupg.org/faq/whats-new-in-2.1.html#nosecring">Removal of the secret keyring</A>
     */
    public static final String GPG_V1_PUBLIC_RING_FILENAME = "pubring.gpg";
    public static final String GPG_V2_PUBLIC_RING_FILENAME = "pubring.kbx";

    /** V1 and V2 known public ring file names in <U>order</U> of preference */
    public static final List<String> PUBLIC_RING_FILES = Collections.unmodifiableList(
            Arrays.asList(GPG_V2_PUBLIC_RING_FILENAME, GPG_V1_PUBLIC_RING_FILENAME));

    /**
     * Holds a {@link Map} whose key=the fingerprint (case <U>insensitive</U>), value=the associated {@link PublicKey}
     */
    protected final AtomicReference<NavigableMap<String, PublicKey>> ringKeys
            = new AtomicReference<>(Collections.emptyNavigableMap());

    public PGPPublicRingWatcher(Path file) {
        super(file);
    }

    @Override
    public List<PublicKey> loadMatchingKeyFingerprints(
            SessionContext session, Collection<String> fingerprints)
            throws IOException, GeneralSecurityException, PGPException {
        int numEntries = GenericUtils.size(fingerprints);
        if (numEntries <= 0) {
            return Collections.emptyList();
        }

        Map<String, PublicKey> keysMap = resolveRingKeys(session);
        if (GenericUtils.isEmpty(keysMap)) {
            return Collections.emptyList();
        }

        List<PublicKey> matches = Collections.emptyList();
        for (String fp : fingerprints) {
            PublicKey key = keysMap.get(fp);
            if (key == null) {
                continue;
            }

            if (GenericUtils.isEmpty(matches)) {
                matches = new ArrayList<>(numEntries);
            }
            matches.add(key);
        }

        return matches;
    }

    protected NavigableMap<String, PublicKey> resolveRingKeys(SessionContext session)
            throws IOException, GeneralSecurityException, PGPException {
        NavigableMap<String, PublicKey> keysMap = ringKeys.get();
        if (GenericUtils.isEmpty(keysMap) || checkReloadRequired()) {
            ringKeys.set(Collections.emptyNavigableMap()); // mark stale

            if (!exists()) {
                return ringKeys.get();
            }

            Path file = getPath();
            keysMap = reloadRingKeys(session, new PathResource(file));

            int numKeys = GenericUtils.size(keysMap);
            if (log.isDebugEnabled()) {
                log.debug("resolveRingKeys({}) reloaded {} keys from {}", session, numKeys, file);
            }

            if (numKeys > 0) {
                ringKeys.set(keysMap);
                updateReloadAttributes();
            }
        }

        return keysMap;
    }

    protected NavigableMap<String, PublicKey> reloadRingKeys(
            SessionContext session, IoResource<?> resourceKey)
            throws IOException, GeneralSecurityException, PGPException {
        Ring ring;
        try (InputStream stream = resourceKey.openInputStream()) {
            ring = new Ring(stream);
        }

        return reloadRingKeys(session, resourceKey, ring);
    }

    protected NavigableMap<String, PublicKey> reloadRingKeys(
            SessionContext session, NamedResource resourceKey, Ring ring)
            throws IOException, GeneralSecurityException, PGPException {
        return reloadRingKeys(session, resourceKey, ring.getKeys());
    }

    protected NavigableMap<String, PublicKey> reloadRingKeys(
            SessionContext session, NamedResource resourceKey, Collection<Key> keys)
            throws IOException, GeneralSecurityException, PGPException {
        if (GenericUtils.isEmpty(keys)) {
            return Collections.emptyNavigableMap();
        }

        NavigableMap<String, PublicKey> keysMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        boolean debugEnabled = log.isDebugEnabled();
        for (Key k : keys) {
            Map<String, Subkey> subKeys = PGPUtils.mapSubKeysByFingerprint(k);
            for (Map.Entry<String, Subkey> se : subKeys.entrySet()) {
                String fp = se.getKey();
                Subkey sk = se.getValue();
                PublicKey pubKey;
                try {
                    pubKey = extractPublicKey(resourceKey, sk);
                } catch (IOException | GeneralSecurityException | RuntimeException e) {
                    pubKey = handlePublicKeyExtractionError(session, resourceKey, fp, sk, e);
                }

                if (debugEnabled) {
                    log.debug("reloadRingKeys({}) loaded {} key ({}) for fingerprint={} from {}",
                            session, KeyUtils.getKeyType(pubKey), KeyUtils.getFingerPrint(pubKey), fp, resourceKey.getName());
                }
                if (pubKey == null) {
                    continue;
                }

                PublicKey prev = keysMap.put(fp, pubKey);
                if (prev != null) {
                    PublicKey effective = handleDuplicateKeyFingerprint(session, resourceKey, fp, sk, prev, pubKey);
                    if (effective == null) {
                        keysMap.remove(fp);
                    } else if (!GenericUtils.isSameReference(effective, pubKey)) {
                        keysMap.put(fp, effective);
                    }
                }
            }
        }

        return keysMap;
    }

    /**
     * Invoked if failed to extract a {@link PublicKey} from a given {@link Subkey}
     *
     * @param  session                  The {@link SessionContext} of the invocation - may be {@code null} if no session
     *                                  context available (e.g., offline tool invocation)
     * @param  resourceKey              A key representing the resource from which the key data was read
     * @param  fingerprint              The fingerprint value
     * @param  subKey                   The {@link Subkey} that contains the failed public key
     * @param  reason                   The reason for the failure
     * @return                          The effective key to use - if {@code null} (default behavior) then sub-key is
     *                                  skipped
     * @throws IOException              If failed to process some internal data stream
     * @throws GeneralSecurityException If failed to generate a surrogate key
     * @throws PGPException             If failed to convert PGP key to Java one
     */
    protected PublicKey handlePublicKeyExtractionError(
            SessionContext session, NamedResource resourceKey, String fingerprint, Subkey subKey, Throwable reason)
            throws IOException, GeneralSecurityException, PGPException {
        log.warn("handlePublicKeyExtractionError({}) failed ({}) to extract value for fingerprint={} from {}: {}",
                session, reason.getClass().getSimpleName(), fingerprint, resourceKey.getName(), reason.getMessage());
        return null;
    }

    /**
     * /** Invoked if duplicate public keys found for the same fingerprint
     *
     * @param  session                  The {@link SessionContext} of the invocation - may be {@code null} if no session
     *                                  context available (e.g., offline tool invocation)
     * @param  resourceKey              A key representing the resource from which the key data was read
     * @param  fingerprint              The duplicate fingerprint
     * @param  subKey                   The {@link Subkey} from which the duplicate originated
     * @param  k1                       The original {@link PublicKey} associated with this fingerprint
     * @param  k2                       The replacing {@link PublicKey} associated for same fingerprint
     * @return                          The effective key to use (default=the replacing one) - if {@code null} then
     *                                  associated for the specified fingerprint is nullified
     * @throws IOException              If failed to process some internal data stream
     * @throws GeneralSecurityException If failed to generate a surrogate key
     * @throws PGPException             If failed to convert PGP key to Java one
     */
    protected PublicKey handleDuplicateKeyFingerprint(
            SessionContext session, NamedResource resourceKey, String fingerprint, Subkey subKey, PublicKey k1, PublicKey k2)
            throws IOException, GeneralSecurityException, PGPException {
        log.warn("handleDuplicateKeyFingerprint({}) duplicate keys found for fingerprint={} ({}[{}] / {}[{}]) in {}",
                session, fingerprint, KeyUtils.getKeyType(k1), KeyUtils.getFingerPrint(k1),
                KeyUtils.getKeyType(k2), KeyUtils.getFingerPrint(k2), resourceKey.getName());
        return k2;
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

    public static Path detectDefaultPublicRingFilePath() {
        return detectDefaultPublicRingFilePath(PGPUtils.getDefaultPgpFolderPath());
    }

    /**
     * Checks if either the {@value #GPG_V1_PUBLIC_RING_FILENAME} or {@value #GPG_V2_PUBLIC_RING_FILENAME} exist as a
     * <U>regular</U> file and can be read. <B>Note:</B> it attempts the V2 file first.
     *
     * @param  dir The directory to look into
     * @return     The resolved {@link Path} - {@code null} if none of the files exists.
     */
    public static Path detectDefaultPublicRingFilePath(Path dir) {
        for (String name : PUBLIC_RING_FILES) {
            Path file = dir.resolve(name);
            if (!Files.exists(file)) {
                continue;
            }
            if (!Files.isRegularFile(file)) {
                continue;
            }
            if (!Files.isReadable(file)) {
                continue;
            }

            return file;
        }

        return null;
    }
}
