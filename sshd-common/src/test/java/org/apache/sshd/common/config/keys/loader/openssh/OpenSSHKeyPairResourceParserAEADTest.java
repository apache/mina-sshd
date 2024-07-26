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

import java.net.URL;
import java.security.KeyPair;
import java.util.Collection;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests reading an ed25519 private key in OpenSSH format AES encrypted and encrypted with AEAD ciphers (AES-GCM and
 * chacha20-poly1305@openssh.com).
 */
@Tag("NoIoTestCase")
public class OpenSSHKeyPairResourceParserAEADTest extends JUnitTestSupport {

    private static final String BASE = "ed25519_priv";

    private String testFileName;

    private KeyPair unencrypted;

    public void initOpenSSHKeyPairResourceParserAEADTest(String fileName) {
        testFileName = fileName;
    }

    public static String[] parameters() {
        return new String[] { BASE + ".aes", BASE + ".cha", BASE + ".gcm" };
    }

    private KeyPair load(String fileName) throws Exception {
        URL url = getClass().getResource(fileName);
        assertNotNull(url, "Missing test resource " + fileName);
        Collection<KeyPair> pairs = OpenSSHKeyPairResourceParser.INSTANCE.loadKeyPairs(null, url, (s, r, i) -> "test");
        assertEquals(1, pairs.size(), "Unexpected number of keys");
        KeyPair result = pairs.iterator().next();
        assertNotNull(result, "No unencrypted key pair");
        return result;
    }

    @BeforeEach
    void loadUnencrypted() throws Exception {
        unencrypted = load(BASE);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    public void decrypt(String fileName) throws Exception {
        initOpenSSHKeyPairResourceParserAEADTest(fileName);
        assertTrue(KeyUtils.compareKeyPairs(unencrypted, load(testFileName)), "Unequal keys");
    }
}
