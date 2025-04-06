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

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.TreeSet;

import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryDataResolver;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.c02e.jpgpj.Key;
import org.c02e.jpgpj.Subkey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
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
class PGPUtilsKeyFingerprintTest extends JUnitTestSupport {
    private Key key;

    void initPGPUtilsKeyFingerprintTest(String resourceName) throws IOException, PGPException {
        InputStream stream = getClass().getResourceAsStream(resourceName);
        assertNotNull(stream, "Missing " + resourceName);

        try {
            key = new Key(stream);
            key.setNoPassphrase(true); // we are scanning public keys which are never encrypted
        } finally {
            stream.close();
        }
    }

    static String[] parameters() {
        return new String[] {
                "EC-256-gpg2-public.asc",
                "EC-348-v1p0-public.asc",
                "EC-521-gpg2-public.asc",
                "RSA-2048-v1p0-public.asc",
                "RSA-2048-v1p6p1-public.asc",
                "RSA-4096-vp2p0p8-public.asc",
                "DSA-2048-gpg4win-3.1.3.asc" };
    }

    @BeforeAll
    @AfterAll
    static void clearAllRegisteredPublicKeyEntryDataResolvers() {
        for (String keyType : PGPPublicKeyEntryDataResolver.PGP_KEY_TYPES) {
            PublicKeyEntry.unregisterKeyDataEntryResolver(keyType);
            KeyUtils.unregisterPublicKeyEntryDecoderForKeyType(keyType);
        }
    }

    @BeforeEach
    void setUp() {
        clearAllRegisteredPublicKeyEntryDataResolvers();
    }

    @AfterEach
    void tearDown() {
        clearAllRegisteredPublicKeyEntryDataResolvers();
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void findSubKeyByFingerprint(String resourceName) throws Exception {
        initPGPUtilsKeyFingerprintTest(resourceName);
        Collection<? extends Subkey> subKeys = key.getSubkeys();
        assertFalse(GenericUtils.isEmpty(subKeys), "No sub keys available in " + resourceName);

        for (Subkey expected : subKeys) {
            String fingerprint = expected.getFingerprint();
            Subkey actual = PGPUtils.findSubkeyByFingerprint(key, fingerprint);
            assertSame(expected, actual, "Mismatched sub-key match for " + fingerprint);
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void parseAuthorizedKeyEntry(String resourceName) throws Exception {
        initPGPUtilsKeyFingerprintTest(resourceName);
        Path dir = getTempTargetRelativeFile(getClass().getSimpleName());
        Path file = Files.createDirectories(dir).resolve(resourceName + ".authorized");
        Collection<? extends Subkey> subKeys = key.getSubkeys();
        assertFalse(GenericUtils.isEmpty(subKeys), "No sub keys available in " + resourceName);

        Collection<String> written = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        try (BufferedWriter out = Files.newBufferedWriter(file, StandardCharsets.UTF_8, IoUtils.EMPTY_OPEN_OPTIONS)) {
            for (Subkey sk : subKeys) {
                String fingerprint = sk.getFingerprint();
                PGPPublicKey publicKey = sk.getPublicKey();
                String keyType = PGPPublicKeyEntryDataResolver.getKeyType(publicKey);
                if (GenericUtils.isEmpty(keyType)) {
                    outputDebugMessage("%s: skip fingerprint=%s due to unknown key type", resourceName, fingerprint);
                    continue;
                }

                out.append(keyType)
                        .append(' ').append(fingerprint)
                        .append(' ').append(resourceName)
                        .append(System.lineSeparator());

                assertTrue(written.add(fingerprint), "Non-unique fingerprint: " + fingerprint);
            }
        }
        // Can happen for ECC or EDDSA keys
        Assumptions.assumeFalse(written.isEmpty(), resourceName + " - no fingerprints written");

        PGPPublicKeyEntryDataResolver.registerDefaultKeyEntryDataResolvers();
        Collection<? extends PublicKeyEntry> authKeys = AuthorizedKeyEntry.readAuthorizedKeys(file, IoUtils.EMPTY_OPEN_OPTIONS);
        assertEquals(written.size(), authKeys.size(), "Mismatched key entries count");

        for (PublicKeyEntry entry : authKeys) {
            PublicKeyEntryDataResolver resolver = entry.getKeyDataResolver();
            assertSame(PGPPublicKeyEntryDataResolver.DEFAULT, resolver, "Mismatched key data resolver for " + entry);

            String fingerprint = resolver.encodeEntryKeyData(entry.getKeyData());
            assertTrue(written.remove(fingerprint), "Unknown fingerprint recovered: " + fingerprint);
        }

        assertTrue(written.isEmpty(), resourceName + " - incomplete fingerprints: " + written);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void resolveAuthorizedEntries(String resourceName)
            throws IOException, GeneralSecurityException, PGPException {
        initPGPUtilsKeyFingerprintTest(resourceName);
        Collection<? extends Subkey> subKeys = key.getSubkeys();
        assertFalse(GenericUtils.isEmpty(subKeys), "No sub keys available in " + resourceName);

        Collection<PublicKeyEntry> available = new ArrayList<>(subKeys.size());
        for (Subkey sk : subKeys) {
            String fingerprint = sk.getFingerprint();
            PGPPublicKey publicKey = sk.getPublicKey();
            String keyType = PGPPublicKeyEntryDataResolver.getKeyType(publicKey);
            if (GenericUtils.isEmpty(keyType)) {
                outputDebugMessage("%s: skip fingerprint=%s due to unknown key type", resourceName, fingerprint);
                continue;
            }

            byte[] keyData = PGPPublicKeyEntryDataResolver.decodeKeyFingerprint(fingerprint);
            PublicKeyEntry pke = new PublicKeyEntry(keyType, keyData);
            available.add(pke);
        }

        // Can happen for ECC or EDDSA keys
        Assumptions.assumeFalse(available.isEmpty(), resourceName + " - no fingerprints extracted");

        Path dir = getTempTargetRelativeFile(getClass().getSimpleName());
        Path file = Files.createDirectories(dir).resolve(resourceName + ".txt");
        try (InputStream input = getClass().getResourceAsStream(resourceName);
             OutputStream output = Files.newOutputStream(file)) {
            IoUtils.copy(input, output);
        }

        PGPAuthorizedEntriesTracker tracker = new PGPAuthorizedEntriesTracker(file);
        SessionContext session = Mockito.mock(SessionContext.class);
        for (PublicKeyEntry pke : available) {
            Collection<PublicKey> keys = tracker.loadMatchingAuthorizedEntries(session, Collections.singletonList(pke));
            assertEquals(1, GenericUtils.size(keys), "Mismatched recovered keys count for " + pke);

            PublicKey expected = pke.resolvePublicKey(session, Collections.emptyMap(), tracker);
            PublicKey actual = GenericUtils.head(keys);
            assertKeyEquals(pke.toString(), expected, actual);
        }
    }
}
