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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class OpenSSHKeyPairResourceParserPasswordTest extends OpenSSHKeyPairResourceParserTestSupport {
    private static final int MAX_RETRIES = 3;

    private ResourceDecodeResult decodeResult;
    private final AtomicInteger retriesCount = new AtomicInteger(0);
    private FilePasswordProvider passwordProvider;

    public void initOpenSSHKeyPairResourceParserPasswordTest(BuiltinIdentities identity, ResourceDecodeResult reportedResult) {
        setIdentity(identity);
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
                        assertNotNull(err, "No error reported");
                        assertEquals(0, retryIndex, "Mismatched retry index");
                        break;
                    case RETRY:
                        if (err != null) {
                            @SuppressWarnings("synthetic-access")
                            int curRetry = retriesCount.getAndIncrement();
                            assertEquals(curRetry, retryIndex, "Mismatched retry index");
                            assertTrue(retryIndex < MAX_RETRIES, "Too many retries: " + retryIndex);
                        } else {
                            assertEquals(MAX_RETRIES, retryIndex, "Mismatched success retries count");
                        }
                        break;
                    default:
                        throw new UnsupportedOperationException("Unsupported decode result: " + reportedResult);
                }

                return reportedResult;
            }
        };
    }

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

    @BeforeEach
    void setUp() {
        retriesCount.set(0);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0} / {1}")
    public void loadEncryptedFileWithPasswordRetry(BuiltinIdentities identity, ResourceDecodeResult reportedResult)
            throws Exception {
        initOpenSSHKeyPairResourceParserPasswordTest(identity, reportedResult);
        try {
            testLoadKeyPairs(true, passwordProvider);
            assertNotSame(ResourceDecodeResult.TERMINATE, decodeResult, "Unexpected success");
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
                assertTrue(GenericUtils.isEmpty(pairs), "Unexpected key pairs recovered");
                assertEquals(0, retriesCount.getAndSet(0), "Mismatched retries count");
                break;

            case RETRY:
                assertEquals(1, GenericUtils.size(pairs), "Mismatched pairs count");
                assertEquals(MAX_RETRIES, retriesCount.getAndSet(0), "Mismatched retries count");
                validateKeyPairSignable(resourceKey, GenericUtils.head(pairs));
                break;

            default:
                fail("Unexpected success to decode " + resourceKey);
        }
    }
}
