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

package org.apache.sshd.openpgp;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.FilePasswordProvider.ResourceDecodeResult;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.bouncycastle.openpgp.PGPException;
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
public class PGPKeyPairResourceParserTest extends JUnitTestSupport {
    public static final String PASSWORD = "super secret passphrase";

    private final String resourceName;
    private final ResourceDecodeResult result;
    private final FilePasswordProvider passwordProvider;
    private final AtomicInteger retriesCount = new AtomicInteger(0);
    private final int maxRetries = 3;

    public PGPKeyPairResourceParserTest(String resourceName, ResourceDecodeResult result, String password) {
        this.resourceName = resourceName;
        this.result = result;
        this.passwordProvider = new FilePasswordProvider() {
            @Override
            @SuppressWarnings("synthetic-access")
            public String getPassword(SessionContext session, NamedResource resourceKey, int retryIndex) throws IOException {
                switch (result) {
                    case IGNORE:
                    case TERMINATE:
                        assertEquals("Mismatched retries invocation count", 0, retryIndex);
                        assertEquals("Mismatched retries tracking count", retryIndex, retriesCount.get());
                        return "qwertyuiop123456!@#$%^";
                    case RETRY: {
                        int count = retriesCount.incrementAndGet();
                        assertEquals("Mismatched retries count", count, retryIndex + 1);
                        if (count == maxRetries) {
                            return PASSWORD;
                        } else {
                            return "retry #" + count;
                        }
                    }
                    default:
                        throw new UnsupportedOperationException("Unknown decode result type: " + result);
                }
            }

            @Override
            @SuppressWarnings("synthetic-access")
            public ResourceDecodeResult handleDecodeAttemptResult(
                    SessionContext session, NamedResource resourceKey, int retryIndex, String password, Exception err)
                    throws IOException, GeneralSecurityException {
                if (err == null) {
                    return null;
                }

                if (result == ResourceDecodeResult.RETRY) {
                    if (retriesCount.get() >= maxRetries) {
                        return ResourceDecodeResult.TERMINATE;
                    }
                }

                return result;
            }

            @Override
            public String toString() {
                return FilePasswordProvider.class.getSimpleName() + "[" + result + "]";
            }
        };
    }

    @Parameters(name = "{0} / {1}")
    public static List<Object[]> parameters() {
        return Collections.unmodifiableList(new ArrayList<Object[]>() {
            // Not serializing it
            private static final long serialVersionUID = 1L;

            {
                for (ResourceDecodeResult result : ResourceDecodeResult.values()) {
                    add(new Object[] { "super-secret-passphrase-RSA-2048-v1p0-private.gpg", result, PASSWORD });
                    add(new Object[] { "super-secret-passphrase-RSA-2048-v1p6p1-private.gpg", result, PASSWORD });
                    add(new Object[] { "super-secret-passphrase-RSA-4096-v2p0p8-private.gpg", result, PASSWORD });
                    add(new Object[] { "super-secret-passphrase-DSA-2048-gpg4win-3.1.3.gpg", result, PASSWORD });
                    add(new Object[] { "super-secret-passphrase-EC-256-gpg2-private.gpg", result, PASSWORD });
                    add(new Object[] { "super-secret-passphrase-EC-384-v1p0-private.gpg", result, PASSWORD });
                    add(new Object[] { "super-secret-passphrase-EC-521-gpg2-private.gpg", result, PASSWORD });
                    // TODO add(new Object[] {"super-secret-passphrase-ed25519-gpg4win-3.1.3.gpg, result", PASSWORD});
                }
            }
        });
    }

    @Test
    public void testDecodePrivateKeyPair() throws IOException, GeneralSecurityException, PGPException {
        InputStream stream = getClass().getResourceAsStream(resourceName);
        assertNotNull("Missing " + resourceName, stream);

        Collection<KeyPair> keys;
        try {
            keys = PGPKeyPairResourceParser.INSTANCE.loadKeyPairs(
                    null, NamedResource.ofName(resourceName), passwordProvider, stream);
        } catch (Exception e) {
            if (result != ResourceDecodeResult.TERMINATE) {
                fail("Mismatched result mode for " + e.getClass().getSimpleName() + "[" + e.getMessage() + "]");
            }
            return;
        } finally {
            stream.close();
        }

        switch (result) {
            case IGNORE:
                assertTrue("Unexpected keys recovered", GenericUtils.isEmpty(keys));
                return;

            case RETRY:
                assertFalse("No keys recovered", GenericUtils.isEmpty(keys));
                break;

            case TERMINATE: // fall through...
            default:
                fail("Unexpected return value on request=" + result + ": " + keys);
        }

        for (KeyPair kp : keys) {
            PublicKey pubKey = kp.getPublic();
            PrivateKey prvKey = kp.getPrivate();
            assertNotNull("No public key for private=" + prvKey, pubKey);
            assertNotNull("No private key for public=" + pubKey, prvKey);

            String pubType = KeyUtils.getKeyType(pubKey);
            String prvType = KeyUtils.getKeyType(prvKey);
            assertEquals("Mismatched public/private key types", pubType, prvType);

            int pubSize = KeyUtils.getKeySize(pubKey);
            int prvSize = KeyUtils.getKeySize(prvKey);
            assertEquals("Mismatched public/private key size", pubSize, prvSize);
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + resourceName + "/" + result + "]";
    }
}
