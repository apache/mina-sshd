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

package org.apache.sshd.client.config.keys;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Map;

import org.apache.sshd.common.config.keys.BuiltinIdentities;
import org.apache.sshd.common.config.keys.IdentityUtils;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class ClientIdentityTest extends JUnitTestSupport {
    public ClientIdentityTest() {
        super();
    }

    @Test
    void loadClientIdentities() throws Exception {
        Path resFolder = getTestResourcesFolder();
        LinkOption[] options = IoUtils.getLinkOptions(true);
        Collection<BuiltinIdentities> expected = EnumSet.noneOf(BuiltinIdentities.class);
        for (BuiltinIdentities type : BuiltinIdentities.VALUES) {
            String fileName = ClientIdentity.getIdentityFileName(type);
            Path file = resFolder.resolve(fileName);
            if (!Files.exists(file, options)) {
                System.out.println("Skip non-existing identity file " + file);
                continue;
            }

            if (!type.isSupported()) {
                System.out.println("Skip unsupported identity file " + file);
                continue;
            }

            expected.add(type);
        }

        Map<String, KeyPair> ids = ClientIdentity.loadDefaultIdentities(
                resFolder,
                false, // don't be strict
                null, // none of the files is password protected
                options);
        assertEquals(GenericUtils.size(expected), MapEntryUtils.size(ids), "Mismatched loaded ids count");

        Collection<KeyPair> pairs = new ArrayList<>(ids.size());
        for (BuiltinIdentities type : BuiltinIdentities.VALUES) {
            if (expected.contains(type)) {
                KeyPair kp = ids.get(type.getName());
                assertNotNull(kp, "No key pair loaded for " + type);
                pairs.add(kp);
            }
        }

        KeyIdentityProvider provider = IdentityUtils.createKeyPairProvider(ids, true /* supported only */);
        assertNotNull(provider, "No provider generated");

        Iterable<KeyPair> keys = provider.loadKeys(null);
        for (KeyPair kp : keys) {
            assertTrue(pairs.remove(kp), "Unexpected loaded key: " + kp);
        }

        assertEquals(0, pairs.size(), "Not all pairs listed");
    }
}
