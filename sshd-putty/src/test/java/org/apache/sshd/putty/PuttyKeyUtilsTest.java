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

package org.apache.sshd.putty;

import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.FilePasswordProvider.ResourceDecodeResult;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.functors.UnaryEquator;
import org.apache.sshd.common.util.io.IoUtils;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
class PuttyKeyUtilsTest extends AbstractPuttyTestSupport {
    static final String PASSWORD = "super secret passphrase";

    private String keyType;
    private String regularFile;
    private String encryptedFile;
    private PuttyKeyPairResourceParser parser;

    void initPuttyKeyUtilsTest(String keyType) {
        this.keyType = keyType;
        this.parser = PuttyKeyUtils.BY_KEY_TYPE.get(keyType);
        this.regularFile = getClass().getSimpleName()
                           + "-" + keyType + "-" + KeyPair.class.getSimpleName()
                           + PuttyKeyPairResourceParser.PPK_FILE_SUFFIX;
        this.encryptedFile = PASSWORD.replace(' ', '-') + "-AES-256-CBC"
                             + "-" + keyType + "-" + KeyPair.class.getSimpleName()
                             + PuttyKeyPairResourceParser.PPK_FILE_SUFFIX;
    }

    static List<Object[]> parameters() {
        return parameterize(PuttyKeyUtils.BY_KEY_TYPE.keySet());
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void canDecodePuttyKeyFile(String keyType) throws IOException, GeneralSecurityException {
        initPuttyKeyUtilsTest(keyType);
        for (String resource : new String[] { regularFile, encryptedFile }) {
            URL url = getClass().getResource(resource);
            if (UnaryEquator.isSameReference(regularFile, resource)) {
                assertNotNull(url, "Missing test resource: " + resource);
            } else {
                if (url == null) {
                    outputDebugMessage("Skip non-existing encrypted file: %s", resource);
                    continue;
                }
            }

            List<String> lines = IoUtils.readAllLines(url);
            NamedResource resourceKey = NamedResource.ofName(resource);
            assertTrue(parser.canExtractKeyPairs(resourceKey, lines), resource + " - can extract key pair");

            for (PuttyKeyPairResourceParser other : PuttyKeyUtils.BY_KEY_TYPE.values()) {
                if (parser == other) {
                    continue;
                }

                assertFalse(other.canExtractKeyPairs(resourceKey, lines),
                        other.getClass().getSimpleName() + "/" + resource + " - unexpected extraction capability");
            }
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void decodePuttyKeyFile(String keyType) throws IOException, GeneralSecurityException {
        initPuttyKeyUtilsTest(keyType);
        URL url = getClass().getResource(regularFile);
        assertNotNull(url, "Missing test resource: " + regularFile);

        Collection<KeyPair> keys = parser.loadKeyPairs(null, url, null);
        assertEquals(1, GenericUtils.size(keys), "Mismatched loaded keys count from " + regularFile);
        assertLoadedKeyPair(regularFile, GenericUtils.head(keys));
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void decodeEncryptedPuttyKeyFile(String keyType) throws IOException, GeneralSecurityException {
        initPuttyKeyUtilsTest(keyType);
        testDecodeEncryptedPuttyKeyFile(encryptedFile, true, PASSWORD, parser, keyType);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void decideEncryptedFileWithRetries(String keyType) throws IOException, GeneralSecurityException {
        initPuttyKeyUtilsTest(keyType);
        Assumptions.assumeTrue(BuiltinCiphers.aes256cbc.isSupported(), BuiltinCiphers.aes256cbc.getTransformation() + " N/A");

        URL url = getClass().getResource(encryptedFile);
        Assumptions.assumeTrue(url != null, "Skip non-existent encrypted file: " + encryptedFile);
        assertNotNull(url, "Missing test resource: " + encryptedFile);

        int maxRetries = 3;
        SessionContext mockSession = Mockito.mock(SessionContext.class);
        for (ResourceDecodeResult result : ResourceDecodeResult.values()) {
            AtomicInteger retriesCount = new AtomicInteger(0);
            FilePasswordProvider provider = new FilePasswordProvider() {
                @Override
                public String getPassword(SessionContext session, NamedResource resourceKey, int retryIndex)
                        throws IOException {
                    assertSame(mockSession, session, "Mismatched session context");

                    switch (result) {
                        case IGNORE:
                        case TERMINATE:
                            assertEquals(0, retryIndex, "Mismatched retries invocation count");
                            assertEquals(retryIndex, retriesCount.get(), "Mismatched retries tracking count");
                            return "qwertyuiop123456!@#$%^";
                        case RETRY: {
                            int count = retriesCount.incrementAndGet();
                            assertEquals(retryIndex + 1, count, "Mismatched retries count");
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
                public ResourceDecodeResult handleDecodeAttemptResult(
                        SessionContext session, NamedResource resourceKey, int retryIndex, String password, Exception err)
                        throws IOException, GeneralSecurityException {
                    assertSame(mockSession, session, "Mismatched session context");
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

            try {
                Collection<KeyPair> keys = parser.loadKeyPairs(mockSession, url, provider);
                if (result == ResourceDecodeResult.IGNORE) {
                    assertEquals(0, GenericUtils.size(keys), "Unexpected loaded keys count from " + encryptedFile);
                    assertEquals(0, retriesCount.get(), "Mismatched " + result + " retries count");
                } else {
                    assertEquals(1, GenericUtils.size(keys), "Mismatched loaded keys count from " + encryptedFile);
                    assertEquals(maxRetries, retriesCount.get(), "Mismatched " + result + " retries count");
                    assertLoadedKeyPair(encryptedFile, GenericUtils.head(keys));
                }
            } catch (IOException | GeneralSecurityException | RuntimeException e) {
                if (result != ResourceDecodeResult.TERMINATE) {
                    throw e;
                }

                assertEquals(0, retriesCount.get(), "Mismatched " + result + " retries count");
            }
        }
    }

    private KeyPair assertLoadedKeyPair(String prefix, KeyPair kp) throws GeneralSecurityException {
        return assertLoadedKeyPair(prefix, kp, keyType);
    }
}
