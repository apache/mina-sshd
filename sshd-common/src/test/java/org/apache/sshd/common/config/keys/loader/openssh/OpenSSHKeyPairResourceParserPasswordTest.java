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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.BuiltinIdentities;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.FilePasswordProvider.ResourceDecodeResult;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.Before;
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
public class OpenSSHKeyPairResourceParserPasswordTest extends OpenSSHKeyPairResourceParserTestSupport {
    private static final int MAX_RETRIES = 3;

    private final ResourceDecodeResult decodeResult;
    private final AtomicInteger retriesCount = new AtomicInteger(0);
    private final FilePasswordProvider passwordProvider;

    public OpenSSHKeyPairResourceParserPasswordTest(
                                                    BuiltinIdentities identity, ResourceDecodeResult reportedResult) {
        super(identity);
        this.decodeResult = reportedResult;
        this.passwordProvider = new FilePasswordProvider() {
            @Override
            public String getPassword(
                    SessionContext session, NamedResource resourceKey, int retryIndex)
                    throws IOException {
                switch (reportedResult) {
                    case RETRY:
                        if (retryIndex >= MAX_RETRIES) {
                            return PASSWORD;
                        }
                        // fall through ...
                    case IGNORE:
                    case TERMINATE:
                        return getCurrentTestName();
                    default:
                        throw new UnsupportedOperationException("Unsupported decode result: " + reportedResult);
                }
            }

            @Override
            public ResourceDecodeResult handleDecodeAttemptResult(
                    SessionContext session, NamedResource resourceKey, int retryIndex, String password, Exception err)
                    throws IOException, GeneralSecurityException {
                switch (reportedResult) {
                    case IGNORE:
                    case TERMINATE:
                        assertNotNull("No error reported", err);
                        assertEquals("Mismatched retry index", 0, retryIndex);
                        break;
                    case RETRY:
                        if (err != null) {
                            @SuppressWarnings("synthetic-access")
                            int curRetry = retriesCount.getAndIncrement();
                            assertEquals("Mismatched retry index", curRetry, retryIndex);
                            assertTrue("Too many retries: " + retryIndex, retryIndex < MAX_RETRIES);
                        } else {
                            assertEquals("Mismatched success retries count", MAX_RETRIES, retryIndex);
                        }
                        break;
                    default:
                        throw new UnsupportedOperationException("Unsupported decode result: " + reportedResult);
                }

                return reportedResult;
            }
        };
    }

    @Parameters(name = "{0} / {1}")
    public static List<Object[]> parameters() {
        return new ArrayList<Object[]>() {
            // Not serializing it
            private static final long serialVersionUID = 1L;

            {
                for (BuiltinIdentities id : BuiltinIdentities.VALUES) {
                    for (ResourceDecodeResult res : ResourceDecodeResult.VALUES) {
                        add(new Object[] { id, res });
                    }
                }
            }
        };
    }

    @Before
    public void setUp() {
        retriesCount.set(0);
    }

    @Test
    public void testLoadEncryptedFileWithPasswordRetry() throws Exception {
        try {
            testLoadKeyPairs(true, passwordProvider);
            assertNotSame("Unexpected success", ResourceDecodeResult.TERMINATE, decodeResult);
        } catch (Exception e) {
            if (decodeResult != ResourceDecodeResult.TERMINATE) {
                throw e;
            }
        }
    }

    @Override
    public String toString() {
        return super.toString() + "[" + decodeResult + "]";
    }

    @Override
    protected void testLoadKeyPairs(
            boolean encrypted, String resourceKey, Collection<KeyPair> pairs, PublicKey pubEntry)
            throws Exception {
        switch (decodeResult) {
            case IGNORE:
                assertTrue("Unexpected key pairs recovered", GenericUtils.isEmpty(pairs));
                assertEquals("Mismatched retries count", 0, retriesCount.getAndSet(0));
                break;

            case RETRY:
                assertEquals("Mismatched pairs count", 1, GenericUtils.size(pairs));
                assertEquals("Mismatched retries count", MAX_RETRIES, retriesCount.getAndSet(0));
                validateKeyPairSignable(resourceKey, GenericUtils.head(pairs));
                break;

            default:
                fail("Unexpected success to decode " + resourceKey);
        }
    }
}
