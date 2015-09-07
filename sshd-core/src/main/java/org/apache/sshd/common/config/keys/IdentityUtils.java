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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.keyprovider.MappedKeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class IdentityUtils {
    private IdentityUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    private static final class LazyDefaultUserHomeFolderHolder {
        private static final Path PATH =
                new File(ValidateUtils.checkNotNullAndNotEmpty(System.getProperty("user.home"), "No user home"))
                        .toPath()
                        .toAbsolutePath()
                        .normalize();
    }

    /**
     * @return The {@link Path} to the currently running user home
     */
    @SuppressWarnings("synthetic-access")
    public static Path getUserHomeFolder() {
        return LazyDefaultUserHomeFolderHolder.PATH;
    }

    /**
     * @param prefix The file name prefix - ignored if {@code null}/empty
     * @param type   The identity type - ignored if {@code null}/empty
     * @param suffix The file name suffix - ignored if {@code null}/empty
     * @return The identity file name or {@code null} if no name
     */
    public static String getIdentityFileName(String prefix, String type, String suffix) {
        if (GenericUtils.isEmpty(type)) {
            return null;
        } else {
            return GenericUtils.trimToEmpty(prefix)
                    + type.toLowerCase() + GenericUtils.trimToEmpty(suffix);
        }
    }

    /**
     * @param ids           A {@link Map} of the loaded identities where key=the identity type,
     *                      value=the matching {@link KeyPair} - ignored if {@code null}/empty
     * @param supportedOnly If {@code true} then ignore identities that are not
     *                      supported internally
     * @return A {@link KeyPair} for the identities - {@code null} if no identities
     * available (e.g., after filtering unsupported ones)
     * @see BuiltinIdentities
     */
    public static KeyPairProvider createKeyPairProvider(Map<String, KeyPair> ids, boolean supportedOnly) {
        if (GenericUtils.isEmpty(ids)) {
            return null;
        }

        Map<String, KeyPair> pairsMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (Map.Entry<String, KeyPair> ide : ids.entrySet()) {
            String type = ide.getKey();
            KeyPair kp = ide.getValue();
            BuiltinIdentities id = BuiltinIdentities.fromName(type);
            if (id == null) {
                id = BuiltinIdentities.fromKeyPair(kp);
            }

            if (supportedOnly && ((id == null) || (!id.isSupported()))) {
                continue;
            }

            String keyType = KeyUtils.getKeyType(kp);
            if (GenericUtils.isEmpty(keyType)) {
                continue;
            }

            KeyPair prev = pairsMap.put(keyType, kp);
            if (prev != null) {
                continue;   // less of an offense if 2 pairs mapped to same key type
            }
        }

        if (GenericUtils.isEmpty(pairsMap)) {
            return null;
        } else {
            return new MappedKeyPairProvider(pairsMap);
        }
    }

    /**
     * @param paths    A {@link Map} of the identities where key=identity type (case
     *                 <U>insensitive</U>), value=the {@link Path} of file with the identity key
     * @param provider A {@link FilePasswordProvider} - may be {@code null}
     *                 if the loaded keys are <U>guaranteed</U> not to be encrypted. The argument
     *                 to {@link FilePasswordProvider#getPassword(String)} is the path of the
     *                 file whose key is to be loaded
     * @param options  The {@link OpenOption}s to use when reading the key data
     * @return A {@link Map} of the identities where key=identity type (case
     * <U>insensitive</U>), value=the {@link KeyPair} of the identity
     * @throws IOException              If failed to access the file system
     * @throws GeneralSecurityException If failed to load the keys
     * @see SecurityUtils#loadKeyPairIdentity(String, InputStream, FilePasswordProvider)
     */
    public static Map<String, KeyPair> loadIdentities(Map<String, ? extends Path> paths, FilePasswordProvider provider, OpenOption... options)
            throws IOException, GeneralSecurityException {
        if (GenericUtils.isEmpty(paths)) {
            return Collections.emptyMap();
        }

        Map<String, KeyPair> ids = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (Map.Entry<String, ? extends Path> pe : paths.entrySet()) {
            String type = pe.getKey();
            Path path = pe.getValue();
            try (InputStream inputStream = Files.newInputStream(path, options)) {
                KeyPair kp = SecurityUtils.loadKeyPairIdentity(path.toString(), inputStream, provider);
                KeyPair prev = ids.put(type, kp);
                ValidateUtils.checkTrue(prev == null, "Multiple keys for type=%s", type);
            }
        }

        return ids;
    }
}
