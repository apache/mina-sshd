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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.Writer;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.NoCloseInputStream;
import org.apache.sshd.common.util.io.NoCloseReader;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.config.keys.AuthorizedKeysAuthenticator;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.experimental.categories.Category;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@Category({ NoIoTestCase.class })
public abstract class AuthorizedKeysTestSupport extends BaseTestSupport {
    protected AuthorizedKeysTestSupport() {
        super();
    }

    protected List<String> writeDefaultSupportedKeys(Path file, OpenOption... options) throws IOException {
        List<String> keyLines = loadDefaultSupportedKeys();
        if (Files.exists(file)) {
            Files.delete(file);
        }

        assertHierarchyTargetFolderExists(file.getParent());

        try (Writer w = Files.newBufferedWriter(file, StandardCharsets.UTF_8, options)) {
            w.append(PublicKeyEntry.COMMENT_CHAR)
                    .append(' ').append(getCurrentTestName())
                    .append(' ').append(String.valueOf(keyLines.size())).append(" remaining keys")
                    .append(IoUtils.EOL);
            for (String l : keyLines) {
                w.append(l).append(IoUtils.EOL);
            }
        }

        return keyLines;
    }

    protected List<String> loadDefaultSupportedKeys() throws IOException {
        return loadSupportedKeys(
                Objects.requireNonNull(
                        getClass().getResource(AuthorizedKeysAuthenticator.STD_AUTHORIZED_KEYS_FILENAME),
                        "Missing resource=" + AuthorizedKeysAuthenticator.STD_AUTHORIZED_KEYS_FILENAME));
    }

    public static List<String> loadSupportedKeys(URL url) throws IOException {
        return loadSupportedKeys(url.openStream(), true);
    }

    public static List<String> loadSupportedKeys(InputStream input, boolean okToClose) throws IOException {
        try (Reader r = new InputStreamReader(
                NoCloseInputStream.resolveInputStream(input, okToClose), StandardCharsets.UTF_8)) {
            return loadSupportedKeys(r, true);
        }
    }

    public static List<String> loadSupportedKeys(Reader rdr, boolean okToClose) throws IOException {
        try (BufferedReader buf = new BufferedReader(NoCloseReader.resolveReader(rdr, okToClose))) {
            return loadSupportedKeys(buf);
        }
    }

    public static List<String> loadSupportedKeys(BufferedReader rdr) throws IOException {
        List<String> keyLines = new ArrayList<>();
        boolean eccSupported = SecurityUtils.isECCSupported();
        for (String l = rdr.readLine(); l != null; l = rdr.readLine()) {
            l = GenericUtils.trimToEmpty(l);
            // filter out empty and comment lines
            if (GenericUtils.isEmpty(l) || (l.charAt(0) == PublicKeyEntry.COMMENT_CHAR)) {
                continue;
            }

            // skip EC keys if ECC not supported
            if (l.contains(ECCurves.Constants.ECDSA_SHA2_PREFIX) && (!eccSupported)) {
                System.out.println("Skip (ECC not supported) " + l);
                continue;
            }

            keyLines.add(l);
        }

        return keyLines;
    }
}
