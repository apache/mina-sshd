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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.TreeSet;

import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryDataResolver;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.c02e.jpgpj.Key;
import org.c02e.jpgpj.Subkey;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class PGPUtilsKeyFingerprintTest extends JUnitTestSupport {
    private final String resourceName;
    private final Key key;

    public PGPUtilsKeyFingerprintTest(String resourceName) throws IOException, PGPException {
        this.resourceName = resourceName;

        InputStream stream = getClass().getResourceAsStream(resourceName);
        assertNotNull("Missing " + resourceName, stream);

        try {
            key = new Key(stream);
            key.setNoPassphrase(true); // we are scanning public keys which are never encrypted
        } finally {
            stream.close();
        }
    }

    @Parameters(name = "{0}")
    public static List<Object[]> parameters() {
        return parameterize(Arrays.asList(
                "EC-256-gpg2-public.asc",
                "EC-348-v1p0-public.asc",
                "EC-521-gpg2-public.asc",
                "RSA-2048-v1p0-public.asc",
                "RSA-2048-v1p6p1-public.asc",
                "RSA-4096-vp2p0p8-public.asc",
                "DSA-2048-gpg4win-3.1.3.asc"));
    }

    @BeforeClass
    @AfterClass
    public static void clearAllRegisteredPublicKeyEntryDataResolvers() {
        for (String keyType : PGPPublicKeyEntryDataResolver.PGP_KEY_TYPES) {
            PublicKeyEntry.unregisterKeyDataEntryResolver(keyType);
            KeyUtils.unregisterPublicKeyEntryDecoderForKeyType(keyType);
        }
    }

    @Before
    public void setUp() {
        clearAllRegisteredPublicKeyEntryDataResolvers();
    }

    @After
    public void tearDown() {
        clearAllRegisteredPublicKeyEntryDataResolvers();
    }

    @Test
    public void testFindSubKeyByFingerprint() {
        Collection<? extends Subkey> subKeys = key.getSubkeys();
        assertFalse("No sub keys available in " + resourceName, GenericUtils.isEmpty(subKeys));

        for (Subkey expected : subKeys) {
            String fingerprint = expected.getFingerprint();
            Subkey actual = PGPUtils.findSubkeyByFingerprint(key, fingerprint);
            assertSame("Mismatched sub-key match for " + fingerprint, expected, actual);
        }
    }

    @Test
    public void testParseAuthorizedKeyEntry() throws IOException {
        Path dir = getTempTargetRelativeFile(getClass().getSimpleName());
        Path file = Files.createDirectories(dir).resolve(resourceName + ".authorized");
        Collection<? extends Subkey> subKeys = key.getSubkeys();
        assertFalse("No sub keys available in " + resourceName, GenericUtils.isEmpty(subKeys));

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

                assertTrue("Non-unique fingerprint: " + fingerprint, written.add(fingerprint));
            }
        }
        // Can happen for ECC or EDDSA keys
        Assume.assumeFalse(resourceName + " - no fingerprints written", written.isEmpty());

        PGPPublicKeyEntryDataResolver.registerDefaultKeyEntryDataResolvers();
        Collection<? extends PublicKeyEntry> authKeys = AuthorizedKeyEntry.readAuthorizedKeys(file, IoUtils.EMPTY_OPEN_OPTIONS);
        assertEquals("Mismatched key entries count", written.size(), authKeys.size());

        for (PublicKeyEntry entry : authKeys) {
            PublicKeyEntryDataResolver resolver = entry.getKeyDataResolver();
            assertSame("Mismatched key data resolver for " + entry, PGPPublicKeyEntryDataResolver.DEFAULT, resolver);

            String fingerprint = resolver.encodeEntryKeyData(entry.getKeyData());
            assertTrue("Unknown fingerprint recovered: " + fingerprint, written.remove(fingerprint));
        }

        assertTrue(resourceName + " - incomplete fingerprints: " + written, written.isEmpty());
    }

    @Test
    public void testResolveAuthorizedEntries()
            throws IOException, GeneralSecurityException, PGPException {
        Collection<? extends Subkey> subKeys = key.getSubkeys();
        assertFalse("No sub keys available in " + resourceName, GenericUtils.isEmpty(subKeys));

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
        Assume.assumeFalse(resourceName + " - no fingerprints extracted", available.isEmpty());

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
            assertEquals("Mismatched recovered keys count for " + pke, 1, GenericUtils.size(keys));

            PublicKey expected = pke.resolvePublicKey(session, Collections.emptyMap(), tracker);
            PublicKey actual = GenericUtils.head(keys);
            assertKeyEquals(pke.toString(), expected, actual);
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + resourceName + "]";
    }
}
