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

package org.apache.sshd.server.config.keys;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Collections;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.function.Function;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.IdentityUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.SshServer;

/**
 * Loads server identity key files - e.g., {@code /etc/ssh/ssh_host_rsa_key}
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    org.apache.sshd.common.util.security.SecurityUtils#getKeyPairResourceParser()
 */
public final class ServerIdentity {

    public static final String ID_FILE_PREFIX = "ssh_host_";
    public static final String ID_FILE_SUFFIX = "_key";

    /**
     * The server's keys configuration multi-value
     */
    public static final String HOST_KEY_CONFIG_PROP = "HostKey";
    public static final String HOST_CERT_CONFIG_PROP = "HostCertificate";

    public static final Function<String, String> ID_GENERATOR = ServerIdentity::getIdentityFileName;

    private ServerIdentity() {
        throw new UnsupportedOperationException("No instance");
    }

    /**
     * Sets the server's {@link KeyPairProvider} with the loaded identities - if any
     *
     * @param  <S>                      The generic server type
     * @param  server                   The {@link SshServer} to configure
     * @param  props                    The {@link Properties} holding the server's configuration - ignored if
     *                                  {@code null}/empty
     * @param  supportedOnly            If {@code true} then ignore identities that are not supported internally
     * @return                          The updated server
     * @throws IOException              If failed to access the file system
     * @throws GeneralSecurityException If failed to load the keys
     * @see                             #loadKeyPairProvider(Properties, boolean, LinkOption...)
     */
    public static <S extends SshServer> S setKeyPairProvider(S server, Properties props, boolean supportedOnly)
            throws IOException, GeneralSecurityException {
        KeyPairProvider provider = loadKeyPairProvider(props, supportedOnly, IoUtils.getLinkOptions(true));
        if (provider != null) {
            server.setKeyPairProvider(provider);
        }

        return server;
    }

    /**
     * @param  props                    The {@link Properties} holding the server's configuration - ignored if
     *                                  {@code null}/empty
     * @param  supportedOnly            If {@code true} then ignore identities that are not supported internally
     * @param  options                  The {@link LinkOption}s to use when checking files existence
     * @return                          A {@link KeyPair} for the identities - {@code null} if no identities available
     *                                  (e.g., after filtering unsupported ones)
     * @throws IOException              If failed to access the file system
     * @throws GeneralSecurityException If failed to load the keys
     * @see                             #loadIdentities(Properties, LinkOption...)
     * @see                             IdentityUtils#createKeyPairProvider(Map, boolean)
     */
    public static KeyPairProvider loadKeyPairProvider(Properties props, boolean supportedOnly, LinkOption... options)
            throws IOException, GeneralSecurityException {
        Map<String, KeyPair> ids = loadIdentities(props, options);
        return IdentityUtils.createKeyPairProvider(ids, supportedOnly);
    }

    /**
     * @param  props                    The {@link Properties} holding the server's configuration - ignored if
     *                                  {@code null}/empty
     * @param  options                  The {@link LinkOption}s to use when checking files existence
     * @return                          A {@link Map} of the identities where key=identity type (case
     *                                  <U>insensitive</U>), value=the {@link KeyPair} of the identity
     * @throws IOException              If failed to access the file system
     * @throws GeneralSecurityException If failed to load the keys
     * @see                             #findIdentities(Properties, LinkOption...)
     */
    public static Map<String, KeyPair> loadIdentities(Properties props, LinkOption... options)
            throws IOException, GeneralSecurityException {
        Map<String, Path> ids = findIdentities(props, options);
        return IdentityUtils.loadIdentities(
                null /* server keys are not loaded in a session context */, ids,
                null /* server key files are never encrypted */, IoUtils.EMPTY_OPEN_OPTIONS);
    }

    /**
     * @param  props       The {@link Properties} holding the server's configuration - ignored if {@code null}/empty
     * @param  options     The {@link LinkOption}s to use when checking files existence
     * @return             A {@link Map} of the found identities where key=the identity type (case <U>insensitive</U>)
     *                     and value=the {@link Path} of the file holding the specific type key
     * @throws IOException If failed to access the file system
     * @see                #getIdentityType(String)
     * @see                #HOST_KEY_CONFIG_PROP
     * @see                org.apache.sshd.common.config.ConfigFileReaderSupport#readConfigFile(Path,
     *                     java.nio.file.OpenOption...)
     */
    public static Map<String, Path> findIdentities(Properties props, LinkOption... options) throws IOException {
        return getLocations(HOST_KEY_CONFIG_PROP, props, options);
    }

    /**
     * @param  props       The {@link Properties} holding the server's configuration - ignored if {@code null}/empty
     * @param  options     The {@link LinkOption}s to use when checking files existence
     * @return             A {@link Map} of the found certificates where key=the identity type (case <U>insensitive</U>)
     *                     and value=the {@link Path} of the file holding the specific type key
     * @throws IOException If failed to access the file system
     * @see                #getIdentityType(String)
     * @see                #HOST_CERT_CONFIG_PROP
     * @see                org.apache.sshd.common.config.ConfigFileReaderSupport#readConfigFile(Path,
     *                     java.nio.file.OpenOption...)
     */
    public static Map<String, Path> findCertificates(Properties props, LinkOption... options) throws IOException {
        return getLocations(HOST_CERT_CONFIG_PROP, props, options);
    }

    private static Map<String, Path> getLocations(String configPropKey, Properties props, LinkOption... options)
            throws IOException {
        if (GenericUtils.isEmpty(props)) {
            return Collections.emptyMap();
        }

        String keyList = props.getProperty(configPropKey);
        String[] paths = GenericUtils.split(keyList, ',');
        if (GenericUtils.isEmpty(paths)) {
            return Collections.emptyMap();
        }

        Map<String, Path> ids = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (String p : paths) {
            File file = new File(p);
            Path path = file.toPath();
            if (!Files.exists(path, options)) {
                continue;
            }

            String type = getIdentityType(path.getFileName().toString());
            if (GenericUtils.isEmpty(type)) {
                type = p; // just in case the file name does not adhere to the standard naming convention
            }
            Path prev = ids.put(type, path);
            ValidateUtils.checkTrue(prev == null, "Multiple mappings for type=%s", type);
        }

        return ids;
    }

    /**
     * @param  name The file name - ignored if {@code null}/empty
     * @return      The identity type - {@code null} if cannot determine it - e.g., does not start/end with the
     *              {@link #ID_FILE_PREFIX}/{@link #ID_FILE_SUFFIX}
     */
    public static String getIdentityType(String name) {
        if (GenericUtils.isEmpty(name)
                || (name.length() <= (ID_FILE_PREFIX.length() + ID_FILE_SUFFIX.length()))
                || (!name.startsWith(ID_FILE_PREFIX))
                || (!name.endsWith(ID_FILE_SUFFIX))) {
            return null;
        } else {
            return name.substring(ID_FILE_PREFIX.length(), name.length() - ID_FILE_SUFFIX.length());
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
}
