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
package org.apache.sshd.client.config.hosts;

import java.io.StringReader;
import java.security.PublicKey;
import java.util.List;

import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.config.keys.UnsupportedSshPublicKey;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("NoIoTestCase")
class KnownHostEntryTest extends JUnitTestSupport {

    @Test
    void testLine() throws Exception {
        List<KnownHostEntry> entries = KnownHostEntry.readKnownHostEntries(
                new StringReader(
                        "[127.0.0.1]:2222 ssh-ed448 AAAAC3NzaC1lZDI1NTE5AAAAIPu6ntmyfSOkqLl3qPxD5XxwW7OONwwSG3KO+TGn+PFu"),
                true);
        assertNotNull(entries);
        assertEquals(1, entries.size());
        KnownHostEntry entry = entries.get(0);
        AuthorizedKeyEntry keyEntry = entry.getKeyEntry();
        assertNotNull(keyEntry);
        assertEquals("ssh-ed448", keyEntry.getKeyType());
        PublicKey pk = keyEntry.resolvePublicKey(null, PublicKeyEntryResolver.UNSUPPORTED);
        assertTrue(pk instanceof UnsupportedSshPublicKey);
        UnsupportedSshPublicKey sshKey = (UnsupportedSshPublicKey) pk;
        assertEquals("ssh-ed448", sshKey.getKeyType());
        assertEquals("ssh-ed448 AAAAC3NzaC1lZDI1NTE5AAAAIPu6ntmyfSOkqLl3qPxD5XxwW7OONwwSG3KO+TGn+PFu",
                PublicKeyEntry.toString(sshKey));
    }
}
