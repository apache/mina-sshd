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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;
import java.util.List;

import org.apache.sshd.common.config.keys.BuiltinIdentities;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PrivateKeyEntryDecoder;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
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
public class OpenSSHKeyPairResourceParserDecodingTest extends OpenSSHKeyPairResourceParserTestSupport {
    public OpenSSHKeyPairResourceParserDecodingTest(BuiltinIdentities identity) {
        super(identity);
    }

    @Parameters(name = "type={0}")
    public static List<Object[]> parameters() {
        return parameterize(BuiltinIdentities.VALUES);
    }

    @Test
    public void testLoadUnencryptedKeyPairs() throws Exception {
        testLoadKeyPairs(false, null);
    }

    @Test
    public void testLoadEncryptedKeyPairs() throws Exception {
        testLoadKeyPairs(true, DEFAULT_PASSWORD_PROVIDER);
    }

    @Override
    protected void testLoadKeyPairs(
            boolean encrypted, String resourceKey, Collection<KeyPair> pairs, PublicKey pubEntry)
            throws Exception {
        assertEquals("Mismatched pairs count", 1, GenericUtils.size(pairs));

        Class<? extends PublicKey> pubType = identity.getPublicKeyType();
        Class<? extends PrivateKey> prvType = identity.getPrivateKeyType();
        Collection<String> supportedTypeNames = identity.getSupportedKeyTypes();
        for (KeyPair kp : pairs) {
            PublicKey pubKey = kp.getPublic();
            assertObjectInstanceOf("Mismatched public key type", pubType, pubKey);
            assertKeyEquals("Mismatched identity public key", pubEntry, pubKey);

            PrivateKey prvKey = kp.getPrivate();
            assertObjectInstanceOf("Mismatched private key type", prvType, prvKey);

            String pubName = KeyUtils.getKeyType(pubKey);
            String prvName = KeyUtils.getKeyType(prvKey);
            assertEquals("Mismatched reported key type names", pubName, prvName);

            if (!supportedTypeNames.contains(pubName)) {
                fail("Unsupported key type name (" + pubName + "): " + supportedTypeNames);
            }

            validateKeyPairSignable(pubName, kp);

            @SuppressWarnings("rawtypes")
            PrivateKeyEntryDecoder decoder = OpenSSHKeyPairResourceParser.getPrivateKeyEntryDecoder(prvKey);
            assertNotNull("No private key decoder", decoder);

            if (decoder.isPublicKeyRecoverySupported()) {
                @SuppressWarnings("unchecked")
                PublicKey recKey = decoder.recoverPublicKey(prvKey);
                assertKeyEquals("Mismatched recovered public key", pubKey, recKey);
            }
        }
    }
}
