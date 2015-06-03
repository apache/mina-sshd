/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.server.config.keys;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Writer;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.util.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AuthorizedKeysAuthenticatorTest extends BaseTestSupport {
    public AuthorizedKeysAuthenticatorTest() {
        super();
    }

    @Test
    public void testAutomaticReload() throws Exception {
        final Path file=new File(new File(detectTargetFolder(), TEMP_SUBFOLDER_NAME), getCurrentTestName()).toPath();
        if (Files.exists(file)) {
            Files.delete(file);
        }

        final AtomicInteger reloadCount = new AtomicInteger(0);
        PublickeyAuthenticator  auth = new AuthorizedKeysAuthenticator(file) {
                @Override
                protected Collection<AuthorizedKeyEntry> reloadAuthorizedKeys(Path path, String username, ServerSession session) throws IOException {
                    assertSame("Mismatched reload path", file, path);
                    reloadCount.incrementAndGet();
                    return super.reloadAuthorizedKeys(path, username, session);
                }
            };
        assertFalse("Unexpected authentication success for missing file " + file, auth.authenticate(getCurrentTestName(), Mockito.mock(PublicKey.class), null));

        URL url = getClass().getResource(AuthorizedKeyEntry.STD_AUTHORIZED_KEYS_FILENAME);
        assertNotNull("Missing " + AuthorizedKeyEntry.STD_AUTHORIZED_KEYS_FILENAME + " resource", url);

        List<String> lines = new ArrayList<String>();
        try(BufferedReader rdr = new BufferedReader(new InputStreamReader(url.openStream(), StandardCharsets.UTF_8))) {
            for (String l = rdr.readLine(); l != null; l = rdr.readLine()) {
                l = GenericUtils.trimToEmpty(l);
                // filter out empty and comment lines
                if (GenericUtils.isEmpty(l) || (l.charAt(0) == PublicKeyEntry.COMMENT_CHAR)) {
                    continue;
                } else {
                    lines.add(l);
                }
            }
        }

        assertHierarchyTargetFolderExists(file.getParent());
        
        final String EOL = System.getProperty("line.separator");
        Random rnd = new Random(System.nanoTime());
        List<String> removed = new ArrayList<String>(lines.size());
        for ( ; ; ) {
            try(Writer w = Files.newBufferedWriter(file)) {
                for (String l : lines) {
                    w.append(l).append(EOL);
                }
            }

            Collection<AuthorizedKeyEntry> entries = AuthorizedKeyEntry.readAuthorizedKeys(file);
            Collection<PublicKey>  keySet = AuthorizedKeyEntry.resolveAuthorizedKeys(entries);

            reloadCount.set(0);
            for (PublicKey k : keySet) {
                assertTrue("Failed to authenticate with key=" + k.getAlgorithm() + " on file=" + file, auth.authenticate(getCurrentTestName(), k, null));
                // we expect EXACTLY ONE re-load call since we did not modify the file during the authentication
                assertEquals("Unexpected extra calls to keys re-loading", 1, reloadCount.get());
            }

            if (lines.isEmpty()) {
                break;
            }

            int nextSize = rnd.nextInt(lines.size());
            while (lines.size() > nextSize) {
                String l = lines.remove(0);
                removed.add(l);
            }
        }

        assertTrue("File no longer exists: " + file, Files.exists(file));
        assertFalse("Unexpected authentication success for empty file " + file, auth.authenticate(getCurrentTestName(), Mockito.mock(PublicKey.class), null));
    }
}
