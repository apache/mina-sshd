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
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class Ssh2PublicKeyEntryDecoderByKeyTypeTest extends JUnitTestSupport {
    private final String keyType;

    public Ssh2PublicKeyEntryDecoderByKeyTypeTest(String keyType) {
        this.keyType = keyType;
    }

    @Parameters(name = "{0}")
    public static List<Object[]> parameters() {
        return new ArrayList<Object[]>() {
            // Not serializing it
            private static final long serialVersionUID = 1L;

            {
                addTestCases(Arrays.asList(KeyPairProvider.SSH_RSA, KeyPairProvider.SSH_DSS));
                if (SecurityUtils.isECCSupported()) {
                    addTestCases(ECCurves.KEY_TYPES);
                }
                if (SecurityUtils.isEDDSACurveSupported()) {
                    addKey(KeyPairProvider.SSH_ED25519);
                }
            }

            private void addTestCases(Collection<String> keys) {
                for (String k : keys) {
                    addKey(k);
                }
            }

            private void addKey(String k) {
                add(new Object[] { k });
            }
        };
    }

    @Test
    public void testDecodePublicKey() throws Exception {
        PublicKey expected;
        try (InputStream keyData = getPublicKeyDataStream("pub")) {
            Collection<? extends PublicKeyEntry> entries = AuthorizedKeyEntry.readAuthorizedKeys(keyData, true);
            List<PublicKey> keys = PublicKeyEntry.resolvePublicKeyEntries(null, entries, null);
            assertEquals("Mismatched expected public entries count", 1, GenericUtils.size(keys));

            expected = keys.get(0);
        }

        PublicKey actual;
        try (InputStream keyData = getPublicKeyDataStream("ssh2")) {
            actual = Ssh2PublicKeyEntryDecoder.INSTANCE.readPublicKey(null, () -> keyType, keyData);
        }

        assertKeyEquals(keyType, expected, actual);
    }

    private InputStream getPublicKeyDataStream(String suffix) {
        String resourceName = keyType + "-" + PublicKey.class.getSimpleName() + "." + suffix;
        InputStream keyData = getClass().getResourceAsStream(resourceName);
        return ValidateUtils.checkNotNull(keyData, "Missing %s file", resourceName);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + keyType + "]";
    }
}
