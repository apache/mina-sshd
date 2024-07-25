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
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.config.keys.AuthorizedKeysAuthenticator;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
public class AuthorizedKeyEntryTest extends AuthorizedKeysTestSupport {
    public AuthorizedKeyEntryTest() {
        super();
    }

    @Test
    void readAuthorizedKeysFile() throws Exception {
        Path file = getTempTargetRelativeFile(getCurrentTestName());
        writeDefaultSupportedKeys(file);
        runAuthorizedKeysTests(AuthorizedKeyEntry.readAuthorizedKeys(file));
    }

    @Test
    void encodePublicKeyEntry() throws Exception {
        List<String> keyLines = loadDefaultSupportedKeys();
        StringBuilder sb = new StringBuilder(Byte.MAX_VALUE);
        for (String line : keyLines) {
            int pos = line.indexOf(' ');
            String data = line;
            String keyType = line.substring(0, pos);
            // assume this happens if starts with login options
            if (KeyUtils.getPublicKeyEntryDecoder(keyType) == null) {
                data = line.substring(pos + 1).trim();
            }

            AuthorizedKeyEntry entry = AuthorizedKeyEntry.parseAuthorizedKeyEntry(data);
            if (sb.length() > 0) {
                sb.setLength(0);
            }

            PublicKey key = entry.appendPublicKey(null, sb, PublicKeyEntryResolver.FAILING);
            assertNotNull(key, "No key for line=" + line);

            String encoded = sb.toString();
            assertEquals(data, encoded, "Mismatched encoded form for line=" + line);
        }
    }

    @Test
    @Disabled("It might cause some exceptions if user's file contains unsupported keys")
    void readDefaultAuthorizedKeysFile() throws Exception {
        Path path = AuthorizedKeysAuthenticator.getDefaultAuthorizedKeysFile();
        assertNotNull(path, "No default location");

        LinkOption[] options = IoUtils.getLinkOptions(true);
        if (!Files.exists(path, options)) {
            outputDebugMessage("Verify non-existing %s", path);
            Collection<AuthorizedKeyEntry> entries = AuthorizedKeysAuthenticator.readDefaultAuthorizedKeys();
            assertTrue(GenericUtils.isEmpty(entries), "Non-empty keys even though file not found: " + entries);
        } else {
            assertFalse(Files.isDirectory(path, options), "Not a file: " + path);
            runAuthorizedKeysTests(AuthorizedKeysAuthenticator.readDefaultAuthorizedKeys());
        }
    }

    @Test
    @Disabled("Used to test specific files")
    void specificFile() throws Exception {
        Path path = Paths.get("C:" + File.separator + "Temp", "id_ed25519" + PublicKeyEntry.PUBKEY_FILE_SUFFIX);
        testReadAuthorizedKeys(AuthorizedKeyEntry.readAuthorizedKeys(path));
    }

    private <C extends Collection<AuthorizedKeyEntry>> C runAuthorizedKeysTests(C entries) throws Exception {
        testReadAuthorizedKeys(entries);
        testAuthorizedKeysAuth(entries);
        return entries;
    }

    private static <C extends Collection<AuthorizedKeyEntry>> C testReadAuthorizedKeys(C entries) throws Exception {
        assertFalse(GenericUtils.isEmpty(entries), "No entries read");

        Exception err = null;
        for (AuthorizedKeyEntry entry : entries) {
            try {
                ValidateUtils.checkNotNull(
                        entry.resolvePublicKey(null, Collections.emptyMap(), PublicKeyEntryResolver.FAILING),
                        "No public key resolved from %s",
                        entry);
            } catch (Exception e) {
                System.err.append("Failed (").append(e.getClass().getSimpleName()).append(')')
                        .append(" to resolve key of entry=").append(entry.toString())
                        .append(": ").println(e.getMessage());
                err = e;
            }
        }

        if (err != null) {
            throw err;
        }

        return entries;
    }

    private PublickeyAuthenticator testAuthorizedKeysAuth(Collection<AuthorizedKeyEntry> entries)
            throws IOException, GeneralSecurityException {
        Collection<PublicKey> keySet = PublicKeyEntry.resolvePublicKeyEntries(null, entries, PublicKeyEntryResolver.FAILING);
        PublickeyAuthenticator auth = PublickeyAuthenticator.fromAuthorizedEntries(
                getCurrentTestName(), null, entries, PublicKeyEntryResolver.FAILING);
        for (PublicKey key : keySet) {
            assertTrue(auth.authenticate(getCurrentTestName(), key, null),
                    "Failed to authenticate with key=" + key.getAlgorithm());
        }

        return auth;
    }
}
