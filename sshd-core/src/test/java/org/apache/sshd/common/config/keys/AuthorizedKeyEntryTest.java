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
import org.junit.FixMethodOrder;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AuthorizedKeyEntryTest extends AuthorizedKeysTestSupport {
    public AuthorizedKeyEntryTest() {
        super();
    }

    @Test
    public void testReadAuthorizedKeysFile() throws Exception {
        Path file = getTempTargetRelativeFile(getCurrentTestName());
        writeDefaultSupportedKeys(file);
        runAuthorizedKeysTests(AuthorizedKeyEntry.readAuthorizedKeys(file));
    }

    @Test
    public void testEncodePublicKeyEntry() throws Exception {
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
            assertNotNull("No key for line=" + line, key);

            String encoded = sb.toString();
            assertEquals("Mismatched encoded form for line=" + line, data, encoded);
        }
    }

    @Test
    @Ignore("It might cause some exceptions if user's file contains unsupported keys")
    public void testReadDefaultAuthorizedKeysFile() throws Exception {
        Path path = AuthorizedKeysAuthenticator.getDefaultAuthorizedKeysFile();
        assertNotNull("No default location", path);

        LinkOption[] options = IoUtils.getLinkOptions(true);
        if (!Files.exists(path, options)) {
            outputDebugMessage("Verify non-existing %s", path);
            Collection<AuthorizedKeyEntry> entries = AuthorizedKeysAuthenticator.readDefaultAuthorizedKeys();
            assertTrue("Non-empty keys even though file not found: " + entries, GenericUtils.isEmpty(entries));
        } else {
            assertFalse("Not a file: " + path, Files.isDirectory(path, options));
            runAuthorizedKeysTests(AuthorizedKeysAuthenticator.readDefaultAuthorizedKeys());
        }
    }

    @Test
    @Ignore("Used to test specific files")
    public void testSpecificFile() throws Exception {
        Path path = Paths.get("C:" + File.separator + "Temp", "id_ed25519.pub");
        testReadAuthorizedKeys(AuthorizedKeyEntry.readAuthorizedKeys(path));
    }

    private <C extends Collection<AuthorizedKeyEntry>> C runAuthorizedKeysTests(C entries) throws Exception {
        testReadAuthorizedKeys(entries);
        testAuthorizedKeysAuth(entries);
        return entries;
    }

    private static <C extends Collection<AuthorizedKeyEntry>> C testReadAuthorizedKeys(C entries) throws Exception {
        assertFalse("No entries read", GenericUtils.isEmpty(entries));

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
            assertTrue("Failed to authenticate with key=" + key.getAlgorithm(),
                    auth.authenticate(getCurrentTestName(), key, null));
        }

        return auth;
    }
}
