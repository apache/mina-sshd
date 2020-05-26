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

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.AuthorizedKeysTestSupport;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AuthorizedKeysAuthenticatorTest extends AuthorizedKeysTestSupport {
    public AuthorizedKeysAuthenticatorTest() {
        super();
    }

    @Test
    public void testAutomaticReload() throws Exception {
        Path file = getTempTargetRelativeFile(getCurrentTestName());
        if (Files.exists(file)) {
            Files.delete(file);
        }

        AtomicInteger reloadCount = new AtomicInteger(0);
        PublickeyAuthenticator auth = new AuthorizedKeysAuthenticator(file) {
            @Override
            protected Collection<AuthorizedKeyEntry> reloadAuthorizedKeys(
                    Path path, String username, ServerSession session)
                    throws IOException, GeneralSecurityException {
                assertSame("Mismatched reload path", file, path);
                reloadCount.incrementAndGet();
                return super.reloadAuthorizedKeys(path, username, session);
            }
        };
        assertFalse("Unexpected authentication success for missing file " + file,
                auth.authenticate(getCurrentTestName(), Mockito.mock(PublicKey.class), null));

        List<String> keyLines = loadDefaultSupportedKeys();
        assertHierarchyTargetFolderExists(file.getParent());

        while (keyLines.size() > 0) {
            try (Writer w = Files.newBufferedWriter(file, StandardCharsets.UTF_8)) {
                w.append(PublicKeyEntry.COMMENT_CHAR)
                        .append(' ').append(getCurrentTestName())
                        .append(' ').append(String.valueOf(keyLines.size())).append(" remaining keys")
                        .append(IoUtils.EOL);
                for (String l : keyLines) {
                    w.append(l).append(IoUtils.EOL);
                }
            }

            List<AuthorizedKeyEntry> entries = AuthorizedKeyEntry.readAuthorizedKeys(file);
            assertEquals("Mismatched number of loaded entries", keyLines.size(), entries.size());

            List<PublicKey> keySet = PublicKeyEntry.resolvePublicKeyEntries(null, entries, PublicKeyEntryResolver.FAILING);
            assertEquals("Mismatched number of loaded keys", entries.size(), keySet.size());

            reloadCount.set(0);
            for (int index = 0; index < keySet.size(); index++) {
                PublicKey k = keySet.get(index);
                String keyData = keyLines.get(index); // we know they are 1-1 matching

                assertTrue("Failed to authenticate with key #" + (index + 1) + " " + k.getAlgorithm() + "[" + keyData
                           + "] on file=" + file,
                        auth.authenticate(getCurrentTestName(), k, null));

                // we expect EXACTLY ONE re-load call since we did not modify the file during the authentication
                assertEquals("Unexpected keys re-loading of " + keyLines.size() + " remaining at key #" + (index + 1)
                             + " on file=" + file,
                        1, reloadCount.get());
            }

            keyLines.remove(0);
        }

        assertTrue("File no longer exists: " + file, Files.exists(file));
        assertFalse("Unexpected authentication success for empty file " + file,
                auth.authenticate(getCurrentTestName(), Mockito.mock(PublicKey.class), null));
    }
}
