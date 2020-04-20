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

package org.apache.sshd.common.config.keys;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Collections;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;

import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.keyprovider.MappedKeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class IdentityUtils {
    private IdentityUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    private static final class LazyDefaultUserHomeFolderHolder {
        private static final Path PATH
                = Paths.get(ValidateUtils.checkNotNullAndNotEmpty(System.getProperty("user.home"), "No user home"))
                        .toAbsolutePath()
                        .normalize();

        private LazyDefaultUserHomeFolderHolder() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }

    /**
     * @return The {@link Path} to the currently running user home
     */
    @SuppressWarnings("synthetic-access")
    public static Path getUserHomeFolder() {
        return LazyDefaultUserHomeFolderHolder.PATH;
    }

    /**
     * @param  prefix The file name prefix - ignored if {@code null}/empty
     * @param  type   The identity type - ignored if {@code null}/empty
     * @param  suffix The file name suffix - ignored if {@code null}/empty
     * @return        The identity file name or {@code null} if no name
     */
    public static String getIdentityFileName(String prefix, String type, String suffix) {
        if (GenericUtils.isEmpty(type)) {
            return null;
        } else {
            return GenericUtils.trimToEmpty(prefix)
                   + type.toLowerCase()
                   + GenericUtils.trimToEmpty(suffix);
        }
    }

    /**
     * @param  ids           A {@link Map} of the loaded identities where key=the identity type, value=the matching
     *                       {@link KeyPair} - ignored if {@code null}/empty
     * @param  supportedOnly If {@code true} then ignore identities that are not supported internally
     * @return               A {@link KeyPair} for the identities - {@code null} if no identities available (e.g., after
     *                       filtering unsupported ones)
     * @see                  BuiltinIdentities
     */
    public static KeyPairProvider createKeyPairProvider(Map<String, KeyPair> ids, boolean supportedOnly) {
        if (GenericUtils.isEmpty(ids)) {
            return null;
        }

        Map<String, KeyPair> pairsMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        ids.forEach((type, kp) -> {
            BuiltinIdentities id = BuiltinIdentities.fromName(type);
            if (id == null) {
                id = BuiltinIdentities.fromKeyPair(kp);
            }

            if (supportedOnly && ((id == null) || (!id.isSupported()))) {
                return;
            }

            String keyType = KeyUtils.getKeyType(kp);
            if (GenericUtils.isEmpty(keyType)) {
                return;
            }

            KeyPair prev = pairsMap.put(keyType, kp);
            if (prev != null) {
                return; // less of an offense if 2 pairs mapped to same key type
            }
        });

        if (GenericUtils.isEmpty(pairsMap)) {
            return null;
        } else {
            return new MappedKeyPairProvider(pairsMap);
        }
    }

    /**
     * @param  session                  The {@link SessionContext} for invoking this load command - may be {@code null}
     *                                  if not invoked within a session context (e.g., offline tool or session unknown).
     * @param  paths                    A {@link Map} of the identities where key=identity type (case
     *                                  <U>insensitive</U>), value=the {@link Path} of file with the identity key
     * @param  provider                 A {@link FilePasswordProvider} - may be {@code null} if the loaded keys are
     *                                  <U>guaranteed</U> not to be encrypted. The argument to
     *                                  {@code FilePasswordProvider#getPassword} is the path of the file whose key is to
     *                                  be loaded
     * @param  options                  The {@link OpenOption}s to use when reading the key data
     * @return                          A {@link NavigableMap} of the identities where key=identity type (case
     *                                  <U>insensitive</U>), value=the {@link KeyPair} of the identity
     * @throws IOException              If failed to access the file system
     * @throws GeneralSecurityException If failed to load the keys
     */
    public static NavigableMap<String, KeyPair> loadIdentities(
            SessionContext session, Map<String, ? extends Path> paths, FilePasswordProvider provider, OpenOption... options)
            throws IOException, GeneralSecurityException {
        if (GenericUtils.isEmpty(paths)) {
            return Collections.emptyNavigableMap();
        }

        NavigableMap<String, KeyPair> ids = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        // Cannot use forEach because the potential for IOExceptions being thrown
        for (Map.Entry<String, ? extends Path> pe : paths.entrySet()) {
            String type = pe.getKey();
            Path path = pe.getValue();
            PathResource location = new PathResource(path, options);
            Iterable<KeyPair> pairs;
            try (InputStream inputStream = location.openInputStream()) {
                pairs = SecurityUtils.loadKeyPairIdentities(session, location, inputStream, provider);
            }

            if (pairs == null) {
                continue;
            }

            for (KeyPair kp : pairs) {
                KeyPair prev = ids.put(type, kp);
                ValidateUtils.checkTrue(prev == null, "Multiple keys for type=%s due to %s", type, path);
            }
        }

        return ids;
    }
}
