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
import java.io.StreamCorruptedException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.keyprovider.KeyTypeIndicator;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.bouncycastle.openpgp.PGPException;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface PGPAuthorizedKeyEntriesLoader extends PGPPublicKeyExtractor, PublicKeyEntryResolver {
    @Override
    default PublicKey resolve(
            SessionContext session, String keyType, byte[] keyData, Map<String, String> headers)
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
            throw new InvalidKeyException(
                    "Failed (" + e.getClass().getSimpleName() + ")"
                                          + " to load key type=" + keyType + " with fingerprint=" + fingerprint
                                          + ": " + e.getMessage(),
                    e);
        }

        int numKeys = GenericUtils.size(keys);
        if (numKeys > 1) {
            throw new StreamCorruptedException(
                    "Multiple matches (" + numKeys + ")"
                                               + " for " + keyType + " fingerprint=" + fingerprint);
        }

        return GenericUtils.head(keys);
    }

    default List<PublicKey> resolveAuthorizedEntries(
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

    default List<PublicKey> loadMatchingAuthorizedEntries(
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
                // noinspection UnnecessaryContinue
                continue; // debug breakpoint
            }
        }

        return loadMatchingKeyFingerprints(session, fingerprints);
    }

    List<PublicKey> loadMatchingKeyFingerprints(
            SessionContext session, Collection<String> fingerprints)
            throws IOException, GeneralSecurityException, PGPException;
}
