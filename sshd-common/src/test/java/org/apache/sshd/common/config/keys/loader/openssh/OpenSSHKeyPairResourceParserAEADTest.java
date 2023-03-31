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
package org.apache.sshd.common.config.keys.loader.openssh;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URL;
import java.security.KeyPair;
import java.util.Collection;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * Tests reading an ed25519 private key in OpenSSH format AES encrypted and encrypted with AEAD ciphers (AES-GCM and
 * chacha20-poly1305@openssh.com).
 */
@RunWith(Parameterized.class)
@Category({ NoIoTestCase.class })
public class OpenSSHKeyPairResourceParserAEADTest {

    private static final String BASE = "ed25519_priv";

    private String testFileName;

    private KeyPair unencrypted;

    public OpenSSHKeyPairResourceParserAEADTest(String fileName) {
        testFileName = fileName;
    }

    @Parameters(name = "{0}")
    public static String[] parameters() {
        return new String[] { BASE + ".aes", BASE + ".cha", BASE + ".gcm" };
    }

    private KeyPair load(String fileName) throws Exception {
        URL url = getClass().getResource(fileName);
        assertNotNull("Missing test resource " + fileName, url);
        Collection<KeyPair> pairs = OpenSSHKeyPairResourceParser.INSTANCE.loadKeyPairs(null, url, (s, r, i) -> "test");
        assertEquals("Unexpected number of keys", 1, pairs.size());
        KeyPair result = pairs.iterator().next();
        assertNotNull("No unencrypted key pair", result);
        return result;
    }

    @Before
    public void loadUnencrypted() throws Exception {
        unencrypted = load(BASE);
    }

    @Test
    public void testDecrypt() throws Exception {
        assertTrue("Unequal keys", KeyUtils.compareKeyPairs(unencrypted, load(testFileName)));
    }
}
