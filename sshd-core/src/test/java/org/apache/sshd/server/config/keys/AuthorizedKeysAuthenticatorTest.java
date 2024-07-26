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
import java.nio.file.attribute.FileTime;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.time.Instant;
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
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
public class AuthorizedKeysAuthenticatorTest extends AuthorizedKeysTestSupport {
    public AuthorizedKeysAuthenticatorTest() {
        super();
    }

    @Test
    void automaticReload() throws Exception {
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
                assertSame(file, path, "Mismatched reload path");
                reloadCount.incrementAndGet();
                return super.reloadAuthorizedKeys(path, username, session);
            }
        };
        assertFalse(auth.authenticate(getCurrentTestName(), Mockito.mock(PublicKey.class), null),
                "Unexpected authentication success for missing file " + file);

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
            Files.setLastModifiedTime(file, FileTime.from(Instant.now().minusSeconds(4)));

            List<AuthorizedKeyEntry> entries = AuthorizedKeyEntry.readAuthorizedKeys(file);
            assertEquals(keyLines.size(), entries.size(), "Mismatched number of loaded entries");

            List<PublicKey> keySet = PublicKeyEntry.resolvePublicKeyEntries(null, entries, PublicKeyEntryResolver.FAILING);
            assertEquals(entries.size(), keySet.size(), "Mismatched number of loaded keys");

            reloadCount.set(0);
            for (int index = 0; index < keySet.size(); index++) {
                PublicKey k = keySet.get(index);
                String keyData = keyLines.get(index); // we know they are 1-1 matching

                assertTrue(auth.authenticate(getCurrentTestName(), k, null),
                        "Failed to authenticate with key #" + (index + 1) + " " + k.getAlgorithm() + "[" + keyData
                                                                             + "] on file=" + file);

                // we expect EXACTLY ONE re-load call since we did not modify the file during the authentication
                assertEquals(1, reloadCount.get(),
                        "Unexpected keys re-loading of " + keyLines.size() + " remaining at key #" + (index + 1)
                                                   + " on file=" + file);
            }

            keyLines.remove(0);
        }

        assertTrue(Files.exists(file), "File no longer exists: " + file);
        assertFalse(auth.authenticate(getCurrentTestName(), Mockito.mock(PublicKey.class), null),
                "Unexpected authentication success for empty file " + file);
    }
}
