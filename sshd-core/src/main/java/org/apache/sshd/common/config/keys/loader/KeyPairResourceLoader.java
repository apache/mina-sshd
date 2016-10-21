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
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.util.io.IoUtils;

/**
 * Loads {@link KeyPair}s from text resources
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface KeyPairResourceLoader {
    /**
     * An empty loader that never fails but always returns an empty list
     */
    KeyPairResourceLoader EMPTY = (resourceKey, passwordProvider, lines) -> Collections.emptyList();

    default Collection<KeyPair> loadKeyPairs(Path path, FilePasswordProvider passwordProvider, OpenOption... options)
            throws IOException, GeneralSecurityException {
        return loadKeyPairs(path, passwordProvider, StandardCharsets.UTF_8, options);
    }

    default Collection<KeyPair> loadKeyPairs(Path path, FilePasswordProvider passwordProvider, Charset cs, OpenOption... options)
            throws IOException, GeneralSecurityException {
        try (InputStream stream = Files.newInputStream(path, options)) {
            return loadKeyPairs(path.toString(), passwordProvider, stream, cs);
        }
    }

    default Collection<KeyPair> loadKeyPairs(URL url, FilePasswordProvider passwordProvider)
            throws IOException, GeneralSecurityException {
        return loadKeyPairs(url, passwordProvider, StandardCharsets.UTF_8);
    }

    default Collection<KeyPair> loadKeyPairs(URL url, FilePasswordProvider passwordProvider, Charset cs)
            throws IOException, GeneralSecurityException {
        try (InputStream stream = Objects.requireNonNull(url, "No URL").openStream()) {
            return loadKeyPairs(url.toExternalForm(), passwordProvider, stream, cs);
        }
    }

    default Collection<KeyPair> loadKeyPairs(String resourceKey, FilePasswordProvider passwordProvider, String data)
            throws IOException, GeneralSecurityException {
        try (Reader reader = new StringReader((data == null) ? "" : data)) {
            return loadKeyPairs(resourceKey, passwordProvider, reader);
        }
    }

    default Collection<KeyPair> loadKeyPairs(String resourceKey, FilePasswordProvider passwordProvider, InputStream stream)
            throws IOException, GeneralSecurityException {
        return loadKeyPairs(resourceKey, passwordProvider, stream, StandardCharsets.UTF_8);
    }

    default Collection<KeyPair> loadKeyPairs(String resourceKey, FilePasswordProvider passwordProvider, InputStream stream, Charset cs)
            throws IOException, GeneralSecurityException {
        try (Reader reader = new InputStreamReader(
                Objects.requireNonNull(stream, "No stream instance"), Objects.requireNonNull(cs, "No charset"))) {
            return loadKeyPairs(resourceKey, passwordProvider, reader);
        }
    }

    default Collection<KeyPair> loadKeyPairs(String resourceKey, FilePasswordProvider passwordProvider, Reader r)
            throws IOException, GeneralSecurityException {
        try (BufferedReader br = new BufferedReader(Objects.requireNonNull(r, "No reader instance"), IoUtils.DEFAULT_COPY_SIZE)) {
            return loadKeyPairs(resourceKey, passwordProvider, br);
        }
    }

    default Collection<KeyPair> loadKeyPairs(String resourceKey, FilePasswordProvider passwordProvider, BufferedReader r)
            throws IOException, GeneralSecurityException {
        return loadKeyPairs(resourceKey, passwordProvider, IoUtils.readAllLines(r));
    }

    /**
     * Loads key pairs from the given resource text lines
     *
     * @param resourceKey A hint as to the origin of the text lines
     * @param passwordProvider The {@link FilePasswordProvider} to use
     * in case the data is encrypted - may be {@code null} if no encrypted
     * data is expected
     * @param lines The {@link List} of lines as read from the resource
     * @return The extracted {@link KeyPair}s - may be {@code null}/empty if none.
     * <B>Note:</B> the resource loader may decide to skip unknown lines if
     * more than one key pair type is encoded in it
     * @throws IOException If failed to process the lines
     * @throws GeneralSecurityException If failed to generate the keys from the
     * parsed data
     */
    Collection<KeyPair> loadKeyPairs(String resourceKey, FilePasswordProvider passwordProvider, List<String> lines)
            throws IOException, GeneralSecurityException;
}
