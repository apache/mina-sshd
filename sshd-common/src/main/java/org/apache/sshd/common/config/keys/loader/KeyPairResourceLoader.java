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

package org.apache.sshd.common.config.keys.loader;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.resource.IoResource;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.apache.sshd.common.util.io.resource.URLResource;

/**
 * Loads {@link KeyPair}s from text resources
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface KeyPairResourceLoader {
    int MAX_CIPHER_NAME_LENGTH = 256;
    int MAX_KEY_TYPE_NAME_LENGTH = 256;
    int MAX_KEY_COMMENT_LENGTH = 1024;
    int MAX_PUBLIC_KEY_DATA_SIZE = 2 * Short.MAX_VALUE;
    int MAX_PRIVATE_KEY_DATA_SIZE = 4 * MAX_PUBLIC_KEY_DATA_SIZE;

    /**
     * An empty loader that never fails but always returns an empty list
     */
    KeyPairResourceLoader EMPTY = (session, resourceKey, passwordProvider, lines) -> Collections.emptyList();

    /**
     * Loads private key data - <B>Note:</B> any non-ASCII characters are assumed to be UTF-8 encoded
     *
     * @param  session                  The {@link SessionContext} for invoking this load command - may be {@code null}
     *                                  if not invoked within a session context (e.g., offline tool or session unknown).
     * @param  path                     The private key file {@link Path}
     * @param  passwordProvider         The {@link FilePasswordProvider} to use in case the data is encrypted - may be
     *                                  {@code null} if no encrypted data is expected
     * @param  options                  The {@link OpenOption}-s to use to access the file data
     * @return                          The extracted {@link KeyPair}s - may be {@code null}/empty if none. <B>Note:</B>
     *                                  the resource loader may decide to skip unknown lines if more than one key pair
     *                                  type is encoded in it
     * @throws IOException              If failed to process the lines
     * @throws GeneralSecurityException If failed to generate the keys from the parsed data
     */
    default Collection<KeyPair> loadKeyPairs(
            SessionContext session, Path path, FilePasswordProvider passwordProvider, OpenOption... options)
            throws IOException, GeneralSecurityException {
        return loadKeyPairs(session, path, passwordProvider, StandardCharsets.UTF_8, options);
    }

    default Collection<KeyPair> loadKeyPairs(
            SessionContext session, Path path, FilePasswordProvider passwordProvider, Charset cs, OpenOption... options)
            throws IOException, GeneralSecurityException {
        return loadKeyPairs(session, new PathResource(path, options), passwordProvider, cs);
    }

    default Collection<KeyPair> loadKeyPairs(
            SessionContext session, URL url, FilePasswordProvider passwordProvider)
            throws IOException, GeneralSecurityException {
        return loadKeyPairs(session, url, passwordProvider, StandardCharsets.UTF_8);
    }

    default Collection<KeyPair> loadKeyPairs(
            SessionContext session, URL url, FilePasswordProvider passwordProvider, Charset cs)
            throws IOException, GeneralSecurityException {
        return loadKeyPairs(session, new URLResource(url), passwordProvider, cs);
    }

    default Collection<KeyPair> loadKeyPairs(
            SessionContext session, IoResource<?> resource, FilePasswordProvider passwordProvider)
            throws IOException, GeneralSecurityException {
        return loadKeyPairs(session, resource, passwordProvider, StandardCharsets.UTF_8);
    }

    default Collection<KeyPair> loadKeyPairs(
            SessionContext session, IoResource<?> resource, FilePasswordProvider passwordProvider, Charset cs)
            throws IOException, GeneralSecurityException {
        try (InputStream stream = Objects.requireNonNull(resource, "No resource data").openInputStream()) {
            return loadKeyPairs(session, resource, passwordProvider, stream, cs);
        }
    }

    default Collection<KeyPair> loadKeyPairs(
            SessionContext session, NamedResource resourceKey, FilePasswordProvider passwordProvider, String data)
            throws IOException, GeneralSecurityException {
        try (Reader reader = new StringReader((data == null) ? "" : data)) {
            return loadKeyPairs(session, resourceKey, passwordProvider, reader);
        }
    }

    default Collection<KeyPair> loadKeyPairs(
            SessionContext session, NamedResource resourceKey, FilePasswordProvider passwordProvider, InputStream stream)
            throws IOException, GeneralSecurityException {
        return loadKeyPairs(session, resourceKey, passwordProvider, stream, StandardCharsets.UTF_8);
    }

    default Collection<KeyPair> loadKeyPairs(
            SessionContext session, NamedResource resourceKey, FilePasswordProvider passwordProvider, InputStream stream,
            Charset cs)
            throws IOException, GeneralSecurityException {
        try (Reader reader = new InputStreamReader(
                Objects.requireNonNull(stream, "No stream instance"), Objects.requireNonNull(cs, "No charset"))) {
            return loadKeyPairs(session, resourceKey, passwordProvider, reader);
        }
    }

    default Collection<KeyPair> loadKeyPairs(
            SessionContext session, NamedResource resourceKey, FilePasswordProvider passwordProvider, Reader r)
            throws IOException, GeneralSecurityException {
        try (BufferedReader br
                = new BufferedReader(Objects.requireNonNull(r, "No reader instance"), IoUtils.DEFAULT_COPY_SIZE)) {
            return loadKeyPairs(session, resourceKey, passwordProvider, br);
        }
    }

    default Collection<KeyPair> loadKeyPairs(
            SessionContext session, NamedResource resourceKey, FilePasswordProvider passwordProvider, BufferedReader r)
            throws IOException, GeneralSecurityException {
        List<String> lines = IoUtils.readAllLines(r);
        try {
            return loadKeyPairs(session, resourceKey, passwordProvider, lines);
        } finally {
            lines.clear(); // clean up sensitive data a.s.a.p.
        }
    }

    /**
     * Loads key pairs from the given resource text lines
     *
     * @param  session                  The {@link SessionContext} for invoking this load command - may be {@code null}
     *                                  if not invoked within a session context (e.g., offline tool or session unknown).
     * @param  resourceKey              A hint as to the origin of the text lines
     * @param  passwordProvider         The {@link FilePasswordProvider} to use in case the data is encrypted - may be
     *                                  {@code null} if no encrypted data is expected
     * @param  lines                    The {@link List} of lines as read from the resource
     * @return                          The extracted {@link KeyPair}s - may be {@code null}/empty if none. <B>Note:</B>
     *                                  the resource loader may decide to skip unknown lines if more than one key pair
     *                                  type is encoded in it
     * @throws IOException              If failed to process the lines
     * @throws GeneralSecurityException If failed to generate the keys from the parsed data
     */
    Collection<KeyPair> loadKeyPairs(
            SessionContext session, NamedResource resourceKey, FilePasswordProvider passwordProvider, List<String> lines)
            throws IOException, GeneralSecurityException;
}
