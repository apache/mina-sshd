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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;
import java.util.List;

import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.BuiltinIdentities;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.PrivateKeyEntryDecoder;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.Assume;
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
@RunWith(Parameterized.class)   // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class OpenSSHKeyPairResourceParserTest extends BaseTestSupport {
    private static final OpenSSHKeyPairResourceParser PARSER = OpenSSHKeyPairResourceParser.INSTANCE;
    private final BuiltinIdentities identity;

    public OpenSSHKeyPairResourceParserTest(BuiltinIdentities identity) {
        this.identity = identity;
    }

    @Parameters(name = "type={0}")
    public static List<Object[]> parameters() {
        return parameterize(BuiltinIdentities.VALUES);
    }

    @Test
    public void testLoadKeyPairs() throws Exception {
        Assume.assumeTrue(identity + " not supported", identity.isSupported());

        String resourceKey = getClass().getSimpleName() + "-" + identity.getName().toUpperCase() + "-" + KeyPair.class.getSimpleName();
        URL urlKeyPair = getClass().getResource(resourceKey);
        assertNotNull("Missing key-pair resource: " + resourceKey, urlKeyPair);

        Collection<KeyPair> pairs = PARSER.loadKeyPairs(urlKeyPair, FilePasswordProvider.EMPTY);
        assertEquals("Mismatched pairs count", 1, GenericUtils.size(pairs));

        URL urlPubKey = getClass().getResource(resourceKey + ".pub");
        assertNotNull("Missing public key resource: " + resourceKey, urlPubKey);

        List<AuthorizedKeyEntry> entries = AuthorizedKeyEntry.readAuthorizedKeys(urlPubKey);
        assertEquals("Mismatched public keys count", 1, GenericUtils.size(entries));

        AuthorizedKeyEntry entry = entries.get(0);
        PublicKey pubEntry = entry.resolvePublicKey(PublicKeyEntryResolver.FAILING);
        assertNotNull("Cannot retrieve public key", pubEntry);

        Class<? extends PublicKey> pubType = identity.getPublicKeyType();
        Class<? extends PrivateKey> prvType = identity.getPrivateKeyType();
        for (KeyPair kp : pairs) {
            PublicKey pubKey = ValidateUtils.checkInstanceOf(kp.getPublic(), pubType, "Mismatched public key type");
            assertKeyEquals("Mismatched identity public key", pubEntry, pubKey);

            PrivateKey prvKey = ValidateUtils.checkInstanceOf(kp.getPrivate(), prvType, "Mismatched private key type");
            @SuppressWarnings("rawtypes")
            PrivateKeyEntryDecoder decoder =
                OpenSSHKeyPairResourceParser.getPrivateKeyEntryDecoder(prvKey);
            assertNotNull("No private key decoder", decoder);

            if (decoder.isPublicKeyRecoverySupported()) {
                @SuppressWarnings("unchecked")
                PublicKey recKey = decoder.recoverPublicKey(prvKey);
                assertKeyEquals("Mismatched recovered public key", pubKey, recKey);
            }
        }
    }
}
