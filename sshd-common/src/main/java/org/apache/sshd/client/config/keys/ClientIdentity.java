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

package org.apache.sshd.client.config.keys;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Function;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.BuiltinIdentities;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.IdentityUtils;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.FileInfoExtractor;
import org.apache.sshd.common.util.io.IoUtils;

/**
 * Provides keys loading capability from the user's keys folder - e.g., {@code id_rsa}
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    org.apache.sshd.common.util.security.SecurityUtils#getKeyPairResourceParser()
 */
public final class ClientIdentity {

    public static final String ID_FILE_PREFIX = "id_";

    public static final String ID_FILE_SUFFIX = "";

    public static final Function<String, String> ID_GENERATOR = ClientIdentity::getIdentityFileName;

    private ClientIdentity() {
        throw new UnsupportedOperationException("No instance");
    }

    /**
     * @param  name The file name - ignored if {@code null}/empty
     * @return      The identity type - {@code null} if cannot determine it - e.g., does not start with the
     *              {@link #ID_FILE_PREFIX}
     */
    public static String getIdentityType(String name) {
        if (GenericUtils.isEmpty(name)
                || (name.length() <= ID_FILE_PREFIX.length())
                || (!name.startsWith(ID_FILE_PREFIX))) {
            return null;
        } else {
            return name.substring(ID_FILE_PREFIX.length());
        }
    }

    public static String getIdentityFileName(NamedResource r) {
        return getIdentityFileName((r == null) ? null : r.getName());
    }

    /**
     * @param  type The identity type - e.g., {@code rsa} - ignored if {@code null}/empty
     * @return      The matching file name for the identity - {@code null} if no name
     * @see         #ID_FILE_PREFIX
     * @see         #ID_FILE_SUFFIX
     * @see         IdentityUtils#getIdentityFileName(String, String, String)
     */
    public static String getIdentityFileName(String type) {
        return IdentityUtils.getIdentityFileName(ID_FILE_PREFIX, type, ID_FILE_SUFFIX);
    }

    /**
     * @param  strict                   If {@code true} then files that do not have the required access rights are
     *                                  excluded from consideration
     * @param  supportedOnly            If {@code true} then ignore identities that are not supported internally
     * @param  provider                 A {@link FilePasswordProvider} - may be {@code null} if the loaded keys are
     *                                  <U>guaranteed</U> not to be encrypted. The argument to
     *                                  {@code FilePasswordProvider#getPassword} is the path of the file whose key is to
     *                                  be loaded
     * @param  options                  The {@link LinkOption}s to apply when checking for existence
     * @return                          A {@link KeyPair} for the identities - {@code null} if no identities available
     *                                  (e.g., after filtering unsupported ones or strict permissions)
     * @throws IOException              If failed to access the file system
     * @throws GeneralSecurityException If failed to load the keys
     * @see                             PublicKeyEntry#getDefaultKeysFolderPath()
     * @see                             #loadDefaultIdentities(Path, boolean, FilePasswordProvider, LinkOption...)
     */
    public static KeyPairProvider loadDefaultKeyPairProvider(
            boolean strict, boolean supportedOnly, FilePasswordProvider provider, LinkOption... options)
            throws IOException, GeneralSecurityException {
        return loadDefaultKeyPairProvider(PublicKeyEntry.getDefaultKeysFolderPath(), strict, supportedOnly, provider, options);
    }

    /**
     * @param  dir                      The folder to scan for the built-in identities
     * @param  strict                   If {@code true} then files that do not have the required access rights are
     *                                  excluded from consideration
     * @param  supportedOnly            If {@code true} then ignore identities that are not supported internally
     * @param  provider                 A {@link FilePasswordProvider} - may be {@code null} if the loaded keys are
     *                                  <U>guaranteed</U> not to be encrypted. The argument to
     *                                  {@code FilePasswordProvider#getPassword} is the path of the file whose key is to
     *                                  be loaded
     * @param  options                  The {@link LinkOption}s to apply when checking for existence
     * @return                          A {@link KeyPair} for the identities - {@code null} if no identities available
     *                                  (e.g., after filtering unsupported ones or strict permissions)
     * @throws IOException              If failed to access the file system
     * @throws GeneralSecurityException If failed to load the keys
     * @see                             #loadDefaultIdentities(Path, boolean, FilePasswordProvider, LinkOption...)
     * @see                             IdentityUtils#createKeyPairProvider(Map, boolean)
     */
    public static KeyPairProvider loadDefaultKeyPairProvider(
            Path dir, boolean strict, boolean supportedOnly, FilePasswordProvider provider, LinkOption... options)
            throws IOException, GeneralSecurityException {
        Map<String, KeyPair> ids = loadDefaultIdentities(dir, strict, provider, options);
        return IdentityUtils.createKeyPairProvider(ids, supportedOnly);
    }

    /**
     * @param  strict                   If {@code true} then files that do not have the required access rights are
     *                                  excluded from consideration
     * @param  provider                 A {@link FilePasswordProvider} - may be {@code null} if the loaded keys are
     *                                  <U>guaranteed</U> not to be encrypted. The argument to
     *                                  {@code FilePasswordProvider#getPassword} is the path of the file whose key is to
     *                                  be loaded
     * @param  options                  The {@link LinkOption}s to apply when checking for existence
     * @return                          A {@link Map} of the found files where key=identity type (case
     *                                  <U>insensitive</U>), value=the {@link KeyPair} of the identity
     * @throws IOException              If failed to access the file system
     * @throws GeneralSecurityException If failed to load the keys
     * @see                             PublicKeyEntry#getDefaultKeysFolderPath()
     * @see                             #loadDefaultIdentities(Path, boolean, FilePasswordProvider, LinkOption...)
     */
    public static Map<String, KeyPair> loadDefaultIdentities(
            boolean strict, FilePasswordProvider provider, LinkOption... options)
            throws IOException, GeneralSecurityException {
        return loadDefaultIdentities(PublicKeyEntry.getDefaultKeysFolderPath(), strict, provider, options);
    }

    /**
     * @param  dir                      The folder to scan for the built-in identities
     * @param  strict                   If {@code true} then files that do not have the required access rights are
     *                                  excluded from consideration
     * @param  provider                 A {@link FilePasswordProvider} - may be {@code null} if the loaded keys are
     *                                  <U>guaranteed</U> not to be encrypted. The argument to
     *                                  {@code FilePasswordProvider#getPassword} is the path of the file whose key is to
     *                                  be loaded
     * @param  options                  The {@link LinkOption}s to apply when checking for existence
     * @return                          A {@link Map} of the found files where key=identity type (case
     *                                  <U>insensitive</U>), value=the {@link KeyPair} of the identity
     * @throws IOException              If failed to access the file system
     * @throws GeneralSecurityException If failed to load the keys
     * @see                             BuiltinIdentities
     */
    public static Map<String, KeyPair> loadDefaultIdentities(
            Path dir, boolean strict, FilePasswordProvider provider, LinkOption... options)
            throws IOException, GeneralSecurityException {
        return loadIdentities(null, dir, strict, BuiltinIdentities.NAMES, ID_GENERATOR, provider, options);
    }

    /**
     * Scans a folder and loads all available identity files
     *
     * @param  session                  The {@link SessionContext} for invoking this load command - may be {@code null}
     *                                  if not invoked within a session context (e.g., offline tool or session unknown).
     * @param  dir                      The {@link Path} of the folder to scan - ignored if not exists
     * @param  strict                   If {@code true} then files that do not have the required access rights are
     *                                  excluded from consideration
     * @param  types                    The identity types - ignored if {@code null}/empty
     * @param  idGenerator              A {@link Function} to derive the file name holding the specified type
     * @param  provider                 A {@link FilePasswordProvider} - may be {@code null} if the loaded keys are
     *                                  <U>guaranteed</U> not to be encrypted. The argument to
     *                                  {@code FilePasswordProvider#getPassword} is the path of the file whose key is to
     *                                  be loaded
     * @param  options                  The {@link LinkOption}s to apply when checking for existence
     * @return                          A {@link Map} of the found files where key=identity type (case
     *                                  <U>insensitive</U>), value=the {@link KeyPair} of the identity
     * @throws IOException              If failed to access the file system
     * @throws GeneralSecurityException If failed to load the keys
     */
    public static Map<String, KeyPair> loadIdentities(
            SessionContext session, Path dir, boolean strict,
            Collection<String> types, Function<? super String, String> idGenerator,
            FilePasswordProvider provider, LinkOption... options)
            throws IOException, GeneralSecurityException {
        Map<String, Path> paths = scanIdentitiesFolder(dir, strict, types, idGenerator, options);
        return IdentityUtils.loadIdentities(session, paths, provider, IoUtils.EMPTY_OPEN_OPTIONS);
    }

    /**
     * Scans a folder for possible identity files
     *
     * @param  dir         The {@link Path} of the folder to scan - ignored if not exists
     * @param  strict      If {@code true} then files that do not have the required access rights are excluded from
     *                     consideration
     * @param  types       The identity types - ignored if {@code null}/empty
     * @param  idGenerator A {@link Function} to derive the file name holding the specified type
     * @param  options     The {@link LinkOption}s to apply when checking for existence
     * @return             A {@link Map} of the found files where key=identity type (case <U>insensitive</U>), value=the
     *                     {@link Path} of the file holding the key
     * @throws IOException If failed to access the file system
     * @see                KeyUtils#validateStrictKeyFilePermissions(Path, LinkOption...)
     */
    public static Map<String, Path> scanIdentitiesFolder(
            Path dir, boolean strict, Collection<String> types, Function<? super String, String> idGenerator,
            LinkOption... options)
            throws IOException {
        if (GenericUtils.isEmpty(types)) {
            return Collections.emptyMap();
        }

        if (!Files.exists(dir, options)) {
            return Collections.emptyMap();
        }

        ValidateUtils.checkTrue(FileInfoExtractor.ISDIR.infoOf(dir, options), "Not a directory: %s", dir);

        Map<String, Path> paths = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (String t : types) {
            String fileName = idGenerator.apply(t);
            Path p = dir.resolve(fileName);
            if (!Files.exists(p, options)) {
                continue;
            }

            if (strict) {
                if (KeyUtils.validateStrictKeyFilePermissions(p, options) != null) {
                    continue;
                }
            }

            Path prev = paths.put(t, p);
            ValidateUtils.checkTrue(prev == null, "Multiple mappings for type=%s", t);
        }

        return paths;
    }
}
