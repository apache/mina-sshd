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

package org.apache.sshd.client.keyverifier;

import java.io.File;
import java.io.IOException;
import java.net.SocketAddress;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.config.hosts.KnownHostEntry;
import org.apache.sshd.client.config.hosts.KnownHostHashValue;
import org.apache.sshd.client.keyverifier.KnownHostsServerKeyVerifier.HostEntryPair;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.random.JceRandomFactory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.Utils;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class KnownHostsServerKeyVerifierTest extends BaseTestSupport {
    private static final String HASHED_HOST = "192.168.1.61";
    private static final Map<String, PublicKey> HOST_KEYS = new TreeMap<String, PublicKey>(String.CASE_INSENSITIVE_ORDER);
    private static Map<String, KnownHostEntry> hostsEntries;
    private static Path entriesFile;

    public KnownHostsServerKeyVerifierTest() {
        super();
    }

    @BeforeClass
    public static void loadHostsEntries() throws Exception {
        URL url = KnownHostsServerKeyVerifierTest.class.getResource(KnownHostEntry.STD_HOSTS_FILENAME);
        assertNotNull("Missing test file resource", url);
        entriesFile = new File(url.toURI()).toPath();
        outputDebugMessage("loadHostsEntries(%s)", entriesFile);
        hostsEntries = loadEntries(entriesFile);

        for (Map.Entry<String, KnownHostEntry> ke : hostsEntries.entrySet()) {
            String host = ke.getKey();
            KnownHostEntry entry = ke.getValue();
            AuthorizedKeyEntry authEntry = ValidateUtils.checkNotNull(entry.getKeyEntry(), "No key extracted from %s", entry);
            PublicKey key = authEntry.resolvePublicKey(PublicKeyEntryResolver.FAILING);
            assertNull("Multiple keys for host=" + host, HOST_KEYS.put(host, key));
        }
    }

    @Test
    public void testNoUpdatesNoNewHostsAuthentication() throws Exception {
        final AtomicInteger delegateCount = new AtomicInteger(0);
        ServerKeyVerifier delegate = new ServerKeyVerifier() {
            @Override
            public boolean verifyServerKey(ClientSession clientSession, SocketAddress remoteAddress, PublicKey serverKey) {
                delegateCount.incrementAndGet();
                fail("verifyServerKey(" + clientSession + ")[" + remoteAddress + "] unexpected invocation");
                return false;
            }
        };

        final AtomicInteger updateCount = new AtomicInteger(0);
        ServerKeyVerifier verifier = new KnownHostsServerKeyVerifier(delegate, createKnownHostsCopy()) {
            @Override
            protected KnownHostEntry updateKnownHostsFile(
                    ClientSession clientSession, SocketAddress remoteAddress, PublicKey serverKey,
                    Path file, Collection<HostEntryPair> knownHosts)
                            throws Exception {
                updateCount.incrementAndGet();
                fail("updateKnownHostsFile(" + clientSession + ")[" + remoteAddress + "] unexpected invocation: " + file);
                return super.updateKnownHostsFile(clientSession, remoteAddress, serverKey, file, knownHosts);
            }

        };

        for (Map.Entry<String, PublicKey> ke : HOST_KEYS.entrySet()) {
            String host = ke.getKey();
            PublicKey serverKey = ke.getValue();
            KnownHostEntry entry = hostsEntries.get(host);
            outputDebugMessage("Verify host=%s", entry);
            assertTrue("Failed to verify server=" + entry, invokeVerifier(verifier, host, serverKey));
            assertEquals("Unexpected delegate invocation for host=" + entry, 0, delegateCount.get());
            assertEquals("Unexpected update invocation for host=" + entry, 0, updateCount.get());
        }
    }

    @Test
    public void testFileUpdatedOnEveryNewHost() throws Exception {
        final AtomicInteger delegateCount = new AtomicInteger(0);
        ServerKeyVerifier delegate = new ServerKeyVerifier() {
            @Override
            public boolean verifyServerKey(ClientSession clientSession, SocketAddress remoteAddress, PublicKey serverKey) {
                delegateCount.incrementAndGet();
                return true;
            }
        };

        Path path = getKnownHostCopyPath();
        Files.deleteIfExists(path);

        final AtomicInteger updateCount = new AtomicInteger(0);
        ServerKeyVerifier verifier = new KnownHostsServerKeyVerifier(delegate, path) {
            @Override
            protected KnownHostEntry updateKnownHostsFile(
                    ClientSession clientSession, SocketAddress remoteAddress, PublicKey serverKey,
                    Path file, Collection<HostEntryPair> knownHosts)
                            throws Exception {
                updateCount.incrementAndGet();
                return super.updateKnownHostsFile(clientSession, remoteAddress, serverKey, file, knownHosts);
            }
        };

        int verificationCount = 0;
        for (Map.Entry<String, PublicKey> ke : HOST_KEYS.entrySet()) {
            String host = ke.getKey();
            PublicKey serverKey = ke.getValue();
            KnownHostEntry entry = hostsEntries.get(host);
            outputDebugMessage("Verify host=%s", entry);
            assertTrue("Failed to verify server=" + entry, invokeVerifier(verifier, host, serverKey));
            verificationCount++;
            assertEquals("Mismatched number of delegate counts for server=" + entry, verificationCount, delegateCount.get());
            assertEquals("Mismatched number of update counts for server=" + entry, verificationCount, updateCount.get());
        }

        // make sure we have all the original entries and ONLY them
        Map<String, KnownHostEntry> updatedEntries = loadEntries(path);
        for (Map.Entry<String, KnownHostEntry> ke : hostsEntries.entrySet()) {
            String host = ke.getKey();
            KnownHostEntry expected = ke.getValue();
            KnownHostEntry actual = updatedEntries.remove(host);
            assertNotNull("No updated entry for host=" + host, actual);

            String expLine = expected.getConfigLine();
            // if original is a list or hashed then replace them with the expected host
            if ((expLine.indexOf(',') > 0) || (expLine.indexOf(KnownHostHashValue.HASHED_HOST_DELIMITER) >= 0)) {
                int pos = expLine.indexOf(' ');
                expLine = host + expLine.substring(pos);
            }

            int pos = expLine.indexOf("comment-");
            if (pos > 0) {
                expLine = expLine.substring(0, pos).trim();
            }

            assertEquals("Mismatched entry data for host=" + host, expLine, actual.getConfigLine());
        }

        assertTrue("Unexpected extra updated hosts: " + updatedEntries, updatedEntries.isEmpty());
    }

    @Test
    public void testWriteHashedHostValues() throws Exception {
        Path path = getKnownHostCopyPath();
        Files.deleteIfExists(path);

        KnownHostsServerKeyVerifier verifier = new KnownHostsServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE, path) {
            @Override
            protected NamedFactory<Mac> getHostValueDigester(ClientSession clientSession, SocketAddress remoteAddress, String hostIdentity) {
                return KnownHostHashValue.DEFAULT_DIGEST;
            }
        };

        ClientFactoryManager manager = Mockito.mock(ClientFactoryManager.class);
        Mockito.when(manager.getRandomFactory()).thenReturn(JceRandomFactory.INSTANCE);

        ClientSession session = Mockito.mock(ClientSession.class);
        Mockito.when(session.getFactoryManager()).thenReturn(manager);
        for (Map.Entry<String, PublicKey> ke : HOST_KEYS.entrySet()) {
            String host = ke.getKey();
            PublicKey serverKey = ke.getValue();
            KnownHostEntry entry = hostsEntries.get(host);
            outputDebugMessage("Write host=%s", entry);

            SocketAddress address = new SshdSocketAddress(host, 7365);
            Mockito.when(session.getConnectAddress()).thenReturn(address);
            assertTrue("Failed to validate server=" + entry, verifier.verifyServerKey(session, address, serverKey));
        }

        // force re-read to ensure all values are hashed
        Collection<HostEntryPair> keys = verifier.reloadKnownHosts(path);
        for (HostEntryPair ke : keys) {
            KnownHostEntry entry = ke.getHostEntry();
            assertNotNull("No hashing for entry=" + entry, entry.getHashedEntry());
        }
        verifier.setLoadedHostsEntries(keys);

        // make sure can still validate the original hosts
        for (Map.Entry<String, PublicKey> ke : HOST_KEYS.entrySet()) {
            String host = ke.getKey();
            PublicKey serverKey = ke.getValue();
            KnownHostEntry entry = hostsEntries.get(host);
            outputDebugMessage("Re-validate host=%s", entry);

            SocketAddress address = new SshdSocketAddress(host, 7365);
            Mockito.when(session.getConnectAddress()).thenReturn(address);
            assertTrue("Failed to re-validate server=" + entry, verifier.verifyServerKey(session, address, serverKey));
        }
    }

    @Test
    public void testRejectModifiedServerKey() throws Exception {
        KeyPair kp = Utils.generateKeyPair(KeyUtils.RSA_ALGORITHM, 1024);
        final PublicKey modifiedKey = kp.getPublic();
        final AtomicInteger acceptCount = new AtomicInteger(0);
        ServerKeyVerifier verifier = new KnownHostsServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE, createKnownHostsCopy()) {
            @Override
            public boolean acceptModifiedServerKey(
                    ClientSession clientSession, SocketAddress remoteAddress,
                    KnownHostEntry entry, PublicKey expected, PublicKey actual) throws Exception {
                acceptCount.incrementAndGet();
                assertSame("Mismatched actual key for " + remoteAddress, modifiedKey, actual);
                return super.acceptModifiedServerKey(clientSession, remoteAddress, entry, expected, actual);
            }
        };

        int validationCount = 0;
        for (Map.Entry<String, KnownHostEntry> ke : hostsEntries.entrySet()) {
            String host = ke.getKey();
            KnownHostEntry entry = ke.getValue();
            outputDebugMessage("Verify host=%s", entry);
            assertFalse("Unexpected to verification success for " + entry, invokeVerifier(verifier, host, modifiedKey));
            validationCount++;
            assertEquals("Mismatched invocation count for host=" + entry, validationCount, acceptCount.get());
        }
    }

    @Test
    public void testAcceptModifiedServerKeyUpdatesFile() throws Exception {
        KeyPair kp = Utils.generateKeyPair(KeyUtils.RSA_ALGORITHM, 1024);
        final PublicKey modifiedKey = kp.getPublic();
        Path path = createKnownHostsCopy();
        ServerKeyVerifier verifier = new KnownHostsServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE, path) {
            @Override
            public boolean acceptModifiedServerKey(
                    ClientSession clientSession, SocketAddress remoteAddress,
                    KnownHostEntry entry, PublicKey expected, PublicKey actual) throws Exception {
                assertSame("Mismatched actual key for " + remoteAddress, modifiedKey, actual);
                return true;
            }
        };

        for (Map.Entry<String, KnownHostEntry> ke : hostsEntries.entrySet()) {
            String host = ke.getKey();
            KnownHostEntry entry = ke.getValue();
            outputDebugMessage("Verify host=%s", entry);
            assertTrue("Failed to verify " + entry, invokeVerifier(verifier, host, modifiedKey));
        }

        String expected = PublicKeyEntry.toString(modifiedKey);
        Map<String, KnownHostEntry> updatedKeys = loadEntries(path);
        for (Map.Entry<String, KnownHostEntry> ke : hostsEntries.entrySet()) {
            String host = ke.getKey();
            KnownHostEntry original = ke.getValue();
            KnownHostEntry updated = updatedKeys.remove(host);
            assertNotNull("No updated entry for " + original, updated);

            String actual = updated.getConfigLine();
            int pos = actual.indexOf(' ');
            if (actual.charAt(0) == KnownHostEntry.MARKER_INDICATOR) {
                for (pos++; pos < actual.length(); pos++) {
                    if (actual.charAt(pos) != ' ') {
                        break;
                    }
                }
                pos = actual.indexOf(' ', pos);
            }

            actual = GenericUtils.trimToEmpty(actual.substring(pos + 1));
            assertEquals("Mismatched updated value for host=" + host, expected, actual);
        }

        assertTrue("Unexpected extra updated entries: " + updatedKeys, updatedKeys.isEmpty());
    }

    private Path createKnownHostsCopy() throws IOException {
        Path file = getKnownHostCopyPath();
        Files.copy(entriesFile, file, StandardCopyOption.REPLACE_EXISTING);
        return file;
    }

    private Path getKnownHostCopyPath() throws IOException {
        Path file = getTempTargetRelativeFile(getClass().getSimpleName(), getCurrentTestName());
        assertHierarchyTargetFolderExists(file.getParent());
        return file;
    }

    private boolean invokeVerifier(ServerKeyVerifier verifier, String host, PublicKey serverKey) {
        SocketAddress address = new SshdSocketAddress(host, 7365);
        ClientSession session = Mockito.mock(ClientSession.class);
        Mockito.when(session.getConnectAddress()).thenReturn(address);
        Mockito.when(session.toString()).thenReturn(getCurrentTestName() + "[" + host + "]");
        return verifier.verifyServerKey(session, address, serverKey);
    }

    private static Map<String, KnownHostEntry> loadEntries(Path file) throws IOException {
        Collection<KnownHostEntry> entries = KnownHostEntry.readKnownHostEntries(file);
        if (GenericUtils.isEmpty(entries)) {
            return Collections.emptyMap();
        }

        Map<String, KnownHostEntry> hostsMap = new TreeMap<String, KnownHostEntry>(String.CASE_INSENSITIVE_ORDER);
        for (KnownHostEntry entry : entries) {
            String line = entry.getConfigLine();
            outputDebugMessage("loadTestLines(%s) processing %s", file, line);
            // extract hosts
            int pos = line.indexOf(' ');
            String patterns = line.substring(0, pos);
            if (entry.getHashedEntry() != null) {
                assertNull("Multiple hashed entries in file", hostsMap.put(HASHED_HOST, entry));
            } else {
                String[] addrs = GenericUtils.split(patterns, ',');
                for (String a : addrs) {
                    assertNull("Multiple entries for address=" + a, hostsMap.put(a, entry));
                }
            }
        }

        return hostsMap;
    }
}
