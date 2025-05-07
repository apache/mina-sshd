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

package org.apache.sshd.common.config.keys.loader.ssh2;

import java.io.InputStream;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
class Ssh2PublicKeyEntryDecoderByKeyTypeTest extends JUnitTestSupport {

    static List<String> parameters() {
        List<String> result = new ArrayList<>();
        result.add(KeyPairProvider.SSH_RSA);
        result.add(KeyPairProvider.SSH_DSS);
        result.addAll(ECCurves.KEY_TYPES);

        if (SecurityUtils.isEDDSACurveSupported()) {
            result.add(KeyPairProvider.SSH_ED25519);
        }
        return result;
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void decodePublicKey(String keyType) throws Exception {
        PublicKey expected;
        try (InputStream keyData = getPublicKeyDataStream(keyType, "pub")) {
            Collection<? extends PublicKeyEntry> entries = AuthorizedKeyEntry.readAuthorizedKeys(keyData, true);
            List<PublicKey> keys = PublicKeyEntry.resolvePublicKeyEntries(null, entries, null);
            assertEquals(1, GenericUtils.size(keys), "Mismatched expected public entries count");

            expected = keys.get(0);
        }

        PublicKey actual;
        try (InputStream keyData = getPublicKeyDataStream(keyType, "ssh2")) {
            actual = Ssh2PublicKeyEntryDecoder.INSTANCE.readPublicKey(null, () -> keyType, keyData);
        }

        assertKeyEquals(keyType, expected, actual);
    }

    private InputStream getPublicKeyDataStream(String keyType, String suffix) {
        String resourceName = keyType + "-" + PublicKey.class.getSimpleName() + "." + suffix;
        InputStream keyData = getClass().getResourceAsStream(resourceName);
        return ValidateUtils.checkNotNull(keyData, "Missing %s file", resourceName);
    }
}
