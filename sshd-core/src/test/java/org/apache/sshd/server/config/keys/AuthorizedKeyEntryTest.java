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

import java.io.File;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.Collection;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.IoUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.util.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AuthorizedKeyEntryTest extends BaseTestSupport {
    public AuthorizedKeyEntryTest() {
        super();
    }

    @Test
    public void testReadAuthorizedKeysFile() throws Exception {
        URL url = getClass().getResource(AuthorizedKeyEntry.STD_AUTHORIZED_KEYS_FILENAME);
        assertNotNull("Missing " + AuthorizedKeyEntry.STD_AUTHORIZED_KEYS_FILENAME + " resource", url);
        
        runAuthorizedKeysTests(AuthorizedKeyEntry.readAuthorizedKeys(url));
    }
    
    @Test
    @Ignore("It might cause some exceptions if user's file contains unsupported keys")
    public void testReadDefaultAuthorizedKeysFile() throws Exception {
        File file = AuthorizedKeyEntry.getDefaultAuthorizedKeysFile();
        assertNotNull("No default location", file);

        Path path = file.toPath();
        LinkOption[] options = IoUtils.getLinkOptions(false);
        if (!Files.exists(path, options)) {
            System.out.append(getCurrentTestName()).append(": verify non-existing ").println(path);
            Collection<AuthorizedKeyEntry> entries = AuthorizedKeyEntry.readDefaultAuthorizedKeys();
            assertTrue("Non-empty keys even though file not found: " + entries, GenericUtils.isEmpty(entries));
        } else {
            assertFalse("Not a file: " + path, Files.isDirectory(path, options));
            runAuthorizedKeysTests(AuthorizedKeyEntry.readDefaultAuthorizedKeys());
        }
    }

    private void runAuthorizedKeysTests(Collection<AuthorizedKeyEntry> entries) throws Exception {
        testReadAuthorizedKeys(entries);
        testAuthorizedKeysAuth(entries);
    }

    private static Collection<AuthorizedKeyEntry> testReadAuthorizedKeys(Collection<AuthorizedKeyEntry> entries) throws Exception {
        assertFalse("No entries read", GenericUtils.isEmpty(entries));
        
        Exception err = null;
        for (AuthorizedKeyEntry entry : entries) {
            try {
                ValidateUtils.checkNotNull(entry.resolvePublicKey(), "No public key resolved from %s", entry);
            } catch(Exception e) {
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
    
    private PublickeyAuthenticator testAuthorizedKeysAuth(Collection<AuthorizedKeyEntry> entries) throws Exception {
        Collection<PublicKey>  keySet = AuthorizedKeyEntry.resolveAuthorizedKeys(entries);
        PublickeyAuthenticator auth = AuthorizedKeyEntry.fromAuthorizedEntries(entries);
        for (PublicKey key : keySet) {
            assertTrue("Failed to authenticate with key=" + key.getAlgorithm(), auth.authenticate(getCurrentTestName(), key, null));
        }
        
        return auth;
    }
}
