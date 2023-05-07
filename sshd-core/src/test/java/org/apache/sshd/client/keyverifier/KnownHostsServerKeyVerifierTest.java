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

import java.io.IOException;
import java.net.SocketAddress;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.config.hosts.HostPatternsHolder;
import org.apache.sshd.client.config.hosts.KnownHostEntry;
import org.apache.sshd.client.config.hosts.KnownHostHashValue;
import org.apache.sshd.client.keyverifier.KnownHostsServerKeyVerifier.HostEntryPair;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
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
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class KnownHostsServerKeyVerifierTest extends BaseTestSupport {
    private static final String HASHED_HOST = "192.168.1.61";
    private static final Map<SshdSocketAddress, List<PublicKey>> HOST_KEYS = new TreeMap<>(SshdSocketAddress.BY_HOST_AND_PORT);
    private static Map<SshdSocketAddress, List<KnownHostEntry>> hostsEntries;
    private static Path entriesFile;

    public KnownHostsServerKeyVerifierTest() {
        super();
    }

    @BeforeClass
    public static void loadHostsEntries() throws Exception {
        URL url = KnownHostsServerKeyVerifierTest.class.getResource(KnownHostEntry.STD_HOSTS_FILENAME);
        assertNotNull("Missing test file resource", url);
        entriesFile = Paths.get(url.toURI());
        outputDebugMessage("loadHostsEntries(%s)", entriesFile);
        hostsEntries = loadEntries(entriesFile);

        // Cannot use forEach because of the potential IOException/GeneralSecurityException being thrown
        for (Map.Entry<SshdSocketAddress, List<KnownHostEntry>> entry : hostsEntries.entrySet()) {
            for (KnownHostEntry knownHostEntry : entry.getValue()) {
                AuthorizedKeyEntry authEntry
                        = ValidateUtils.checkNotNull(knownHostEntry.getKeyEntry(), "No key extracted from %s", entry.getKey());
                PublicKey key = authEntry.resolvePublicKey(null, Collections.emptyMap(), PublicKeyEntryResolver.FAILING);
                HOST_KEYS.computeIfAbsent(entry.getKey(), k -> new ArrayList<>()).add(key);
            }
        }
    }

    @Test
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public void testParallelLoading() {
        KnownHostsServerKeyVerifier verifier
                = new KnownHostsServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE, entriesFile) {
                    @Override
                    public ModifiedServerKeyAcceptor getModifiedServerKeyAcceptor() {
                        return (clientSession, remoteAddress, entry, expected, actual) -> true; // don't care here
                    }

                    @Override
                    protected boolean acceptKnownHostEntries(
                            ClientSession clientSession, SocketAddress remoteAddress, PublicKey serverKey,
                            Collection<HostEntryPair> knownHosts) {
                        if (GenericUtils.isEmpty(knownHosts)) {
                            fail("Loaded known_hosts collection is empty!");
                        }
                        return super.acceptKnownHostEntries(clientSession, remoteAddress, serverKey, knownHosts);
                    }
                };

        ClientFactoryManager manager = Mockito.mock(ClientFactoryManager.class);
        Mockito.when(manager.getRandomFactory()).thenReturn((Factory) JceRandomFactory.INSTANCE);

        HOST_KEYS.forEach((host, list) -> list.forEach(publicKey -> {
            KnownHostEntry entry = hostsEntries.get(host).stream()
                    .filter(key -> key.getKeyEntry().getKeyType().equals(KeyUtils.getKeyType(publicKey)))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("Missing updated key for " + KeyUtils.getKeyType(publicKey)));

            ClientSession session = Mockito.mock(ClientSession.class);
            Mockito.when(session.getFactoryManager()).thenReturn(manager);

            Mockito.when(session.getConnectAddress()).thenReturn(host);
            if ("revoked".equals(entry.getMarker())) {
                assertFalse("Failed to validate server=" + entry, verifier.verifyServerKey(session, host, publicKey));
            } else {
                assertTrue("Failed to validate server=" + entry, verifier.verifyServerKey(session, host, publicKey));
            }
        }));
    }

    @Test
    public void testNoUpdatesNoNewHostsAuthentication() throws Exception {
        AtomicInteger delegateCount = new AtomicInteger(0);
        ServerKeyVerifier delegate = (clientSession, remoteAddress, serverKey) -> {
            delegateCount.incrementAndGet();
            fail("verifyServerKey(" + clientSession + ")[" + remoteAddress + "] unexpected invocation");
            return false;
        };

        AtomicInteger updateCount = new AtomicInteger(0);
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

        HOST_KEYS.forEach((host, list) -> list.forEach(hostKey -> {
            KnownHostEntry entry = hostsEntries.get(host).stream()
                    .filter(key -> key.getKeyEntry().getKeyType().equals(KeyUtils.getKeyType(hostKey)))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("Missing updated key for " + KeyUtils.getKeyType(hostKey)));
            outputDebugMessage("Verify host=%s", entry);
            if ("revoked".equals(entry.getMarker())) {
                assertFalse("Failed to verify server=" + entry, invokeVerifier(verifier, host, hostKey));
            } else {
                assertTrue("Failed to verify server=" + entry, invokeVerifier(verifier, host, hostKey));
            }
            assertEquals("Unexpected delegate invocation for host=" + entry, 0, delegateCount.get());
            assertEquals("Unexpected update invocation for host=" + entry, 0, updateCount.get());
        }));
    }

    @Test
    public void testFileUpdatedOnEveryNewHost() throws Exception {
        AtomicInteger delegateCount = new AtomicInteger(0);
        ServerKeyVerifier delegate = (clientSession, remoteAddress, serverKey) -> {
            delegateCount.incrementAndGet();
            return true;
        };

        Path path = getKnownHostCopyPath();
        Files.deleteIfExists(path);

        AtomicInteger updateCount = new AtomicInteger(0);
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
        // Cannot use forEach because the verification count variable is not effectively final
        for (SshdSocketAddress hostIdentity : HOST_KEYS.keySet()) {
            PublicKey serverKey = HOST_KEYS.get(hostIdentity).get(0);
            KnownHostEntry entry = hostsEntries.get(hostIdentity).stream()
                    .filter(key -> key.getKeyEntry().getKeyType().equals(KeyUtils.getKeyType(serverKey)))
                    .findAny()
                    .orElseThrow(() -> new IllegalStateException("Missing updated key for " + KeyUtils.getKeyType(serverKey)));
            outputDebugMessage("Verify host=%s", entry);
            assertTrue("Failed to verify server=" + entry, invokeVerifier(verifier, hostIdentity, serverKey));
            verificationCount++;
            assertEquals("Mismatched number of delegate counts for server=" + entry, verificationCount, delegateCount.get());
            assertEquals("Mismatched number of update counts for server=" + entry, verificationCount, updateCount.get());
        }

        // make sure we have all the original entries and ONLY them
        Map<SshdSocketAddress, List<KnownHostEntry>> updatedEntries = loadEntries(path);
        hostsEntries.keySet().forEach(hostIdentity -> {
            KnownHostEntry expected = hostsEntries.get(hostIdentity).get(0);

            KnownHostEntry actual = updatedEntries.get(hostIdentity).stream()
                    .filter(key -> key.getKeyEntry().getKeyType().equals(expected.getKeyEntry().getKeyType()))
                    .findAny()
                    .orElseThrow(() -> new IllegalStateException("Missing updated key for " + expected));

            assertTrue("No updated entry for host=" + hostIdentity, updatedEntries.get(hostIdentity).remove(actual));
            if (updatedEntries.get(hostIdentity).isEmpty()) {
                updatedEntries.remove(hostIdentity);
            }

            String expLine = expected.getConfigLine().replace("@revoked ", "");
            // if original is a list or hashed then replace them with the expected host
            if ((expLine.indexOf(',') > 0) || (expLine.indexOf(KnownHostHashValue.HASHED_HOST_DELIMITER) >= 0)) {
                int pos = expLine.indexOf(' ');
                expLine = hostIdentity.getHostName() + expLine.substring(pos);
            }

            int pos = expLine.indexOf("comment-");
            if (pos > 0) {
                expLine = expLine.substring(0, pos).trim();
            }

            assertEquals("Mismatched entry data for host=" + hostIdentity, expLine, actual.getConfigLine());
        });

        assertTrue("Unexpected extra updated hosts: " + updatedEntries, updatedEntries.isEmpty());
    }

    @Test
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public void testWriteHashedHostValues() throws Exception {
        Path path = getKnownHostCopyPath();
        Files.deleteIfExists(path);

        KnownHostsServerKeyVerifier verifier = new KnownHostsServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE, path) {
            @Override
            protected NamedFactory<Mac> getHostValueDigester(
                    ClientSession clientSession, SocketAddress remoteAddress, SshdSocketAddress hostIdentity) {
                return KnownHostHashValue.DEFAULT_DIGEST;
            }
        };

        ClientFactoryManager manager = Mockito.mock(ClientFactoryManager.class);
        Mockito.when(manager.getRandomFactory()).thenReturn((Factory) JceRandomFactory.INSTANCE);

        ClientSession session = Mockito.mock(ClientSession.class);
        Mockito.when(session.getFactoryManager()).thenReturn(manager);
        HOST_KEYS.keySet().forEach(host -> {
            PublicKey serverKey = HOST_KEYS.get(host).get(0);
            KnownHostEntry entry = hostsEntries.get(host).stream()
                    .filter(key -> key.getKeyEntry().getKeyType().equals(KeyUtils.getKeyType(serverKey)))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("Missing updated key for " + KeyUtils.getKeyType(serverKey)));
            outputDebugMessage("Write host=%s", entry);

            Mockito.when(session.getConnectAddress()).thenReturn(host);
            assertTrue("Failed to validate server=" + entry, verifier.verifyServerKey(session, host, serverKey));
        });

        // force re-read to ensure all values are hashed
        Collection<HostEntryPair> keys = verifier.reloadKnownHosts(session, path);
        for (HostEntryPair ke : keys) {
            KnownHostEntry entry = ke.getHostEntry();
            assertNotNull("No hashing for entry=" + entry, entry.getHashedEntry());
        }
        verifier.setLoadedHostsEntries(keys);

        // make sure can still validate the original hosts
        HOST_KEYS.keySet().forEach(host -> {
            PublicKey serverKey = HOST_KEYS.get(host).get(0);
            KnownHostEntry entry = hostsEntries.get(host).stream()
                    .filter(key -> key.getKeyEntry().getKeyType().equals(KeyUtils.getKeyType(serverKey)))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("Missing updated key for " + KeyUtils.getKeyType(serverKey)));
            outputDebugMessage("Re-validate host=%s", entry);

            Mockito.when(session.getConnectAddress()).thenReturn(host);
            assertTrue("Failed to re-validate server=" + entry, verifier.verifyServerKey(session, host, serverKey));
        });
    }

    @Test
    public void testRejectModifiedServerKey() throws Exception {
        KeyPair kp = CommonTestSupportUtils.generateKeyPair(KeyUtils.RSA_ALGORITHM, 1024);
        PublicKey modifiedKey = kp.getPublic();
        AtomicInteger acceptCount = new AtomicInteger(0);
        AtomicInteger unknownCount = new AtomicInteger(0);
        KnownHostsServerKeyVerifier verifier
                = new KnownHostsServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE, createKnownHostsCopy()) {
                    @Override
                    public boolean acceptModifiedServerKey(
                            ClientSession clientSession, SocketAddress remoteAddress,
                            KnownHostEntry entry, PublicKey expected, PublicKey actual)
                            throws Exception {
                        acceptCount.incrementAndGet();
                        assertNull("Unexpected marker for " + remoteAddress, entry.getMarker());
                        assertSame("Mismatched actual key for " + remoteAddress, modifiedKey, actual);
                        return super.acceptModifiedServerKey(clientSession, remoteAddress, entry, expected, actual);
                    }

                    @Override
                    protected boolean acceptUnknownHostKey(
                            ClientSession clientSession, SocketAddress remoteAddress, PublicKey serverKey) {
                        unknownCount.incrementAndGet();
                        return false;
                    }
                };

        ClientSession session = Mockito.mock(ClientSession.class);

        int validationCount = 0;
        int validUnknownCount = 0;
        // Cannot use forEach because the validation count variable is not effectively final
        for (Map.Entry<SshdSocketAddress, List<KnownHostEntry>> ke : hostsEntries.entrySet()) {
            SshdSocketAddress hostIdentity = ke.getKey();
            for (KnownHostEntry entry : ke.getValue()) {
                outputDebugMessage("Verify host=%s", entry);
                assertFalse("Unexpected to verification success for " + entry,
                        invokeVerifier(verifier, hostIdentity, modifiedKey));
                long acceptedCount = ke.getValue().stream()
                        .filter(k -> verifier.acceptKnownHostEntry(session, hostIdentity, modifiedKey, k))
                        .count();
                if (acceptedCount == 0) {
                    validUnknownCount++;
                } else {
                    validationCount += acceptedCount;
                }
                assertEquals("Mismatched invocation count (acceptModifiedServerKey) for host=" + entry, validationCount,
                        acceptCount.get());
                assertEquals("Mismatched invocation count (acceptUnknownHostKey) host=" + entry, validUnknownCount,
                        unknownCount.get());
            }
        }
    }

    @Test
    public void testAcceptModifiedServerKeyUpdatesFile() throws Exception {
        KeyPair kp = CommonTestSupportUtils.generateKeyPair(KeyUtils.RSA_ALGORITHM, 1024);
        PublicKey modifiedKey = kp.getPublic();
        Path path = createKnownHostsCopy();
        Files.deleteIfExists(path);
        ServerKeyVerifier verifier = new KnownHostsServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE, path) {
            @Override
            public boolean acceptModifiedServerKey(
                    ClientSession clientSession, SocketAddress remoteAddress,
                    KnownHostEntry entry, PublicKey expected, PublicKey actual)
                    throws Exception {
                assertSame("Mismatched actual key for " + remoteAddress, modifiedKey, actual);
                return true;
            }
        };

        hostsEntries.forEach((host, list) -> {
            outputDebugMessage("Verify host=%s", host);
            assertTrue("Failed to verify " + host, invokeVerifier(verifier, host, modifiedKey));
        });

        String expected = PublicKeyEntry.toString(modifiedKey);
        Map<SshdSocketAddress, List<KnownHostEntry>> updatedKeys = loadEntries(path);
        hostsEntries.keySet().forEach(host -> {
            KnownHostEntry updated = updatedKeys.get(host).stream()
                    .filter(key -> key.getKeyEntry().getKeyType().equals(KeyUtils.getKeyType(modifiedKey)))
                    .findAny()
                    .orElseThrow(
                            () -> new IllegalStateException("Missing updated key for " + KeyUtils.getKeyType(modifiedKey)));
            updatedKeys.get(host).remove(updated);
            if (updatedKeys.get(host).isEmpty()) {
                updatedKeys.remove(host);
            }

            String actual = updated.getConfigLine();
            assertNotNull("No updated entry for " + hostsEntries.get(host), actual);
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
        });

        assertTrue("Unexpected extra updated entries: " + updatedKeys, updatedKeys.isEmpty());
    }

    @Test   // SSHD-1063
    public void testUpdateSameHost2PortsStdFirstSameKey() throws Exception {
        testUpdateSameHostWithDifferentPorts(SshConstants.DEFAULT_PORT, 2020, true);
    }

    @Test   // SSHD-1063
    public void testUpdateSameHost2PortsStdLastSameKey() throws Exception {
        testUpdateSameHostWithDifferentPorts(2020, SshConstants.DEFAULT_PORT, true);
    }

    @Test   // SSHD-1063
    public void testUpdateSameHost2NonStdPortsSameKey() throws Exception {
        testUpdateSameHostWithDifferentPorts(2020, 2222, true);
    }

    @Test   // SSHD-1063
    public void testUpdateSameHost2PortsStdFirstDiffKeys() throws Exception {
        testUpdateSameHostWithDifferentPorts(SshConstants.DEFAULT_PORT, 2020, false);
    }

    @Test   // SSHD-1063
    public void testUpdateSameHost2PortsStdLastDiffKeys() throws Exception {
        testUpdateSameHostWithDifferentPorts(2020, SshConstants.DEFAULT_PORT, false);
    }

    @Test   // SSHD-1063
    public void testUpdateSameHost2NonStdPortsDiffKeys() throws Exception {
        testUpdateSameHostWithDifferentPorts(2020, 2222, false);
    }

    private void testUpdateSameHostWithDifferentPorts(int port1, int port2, boolean useSameKey) throws Exception {
        Path path = getKnownHostCopyPath();
        Files.write(path, Collections.singletonList(""));   // start empty
        // accept all unknown entries
        KnownHostsServerKeyVerifier verifier = new KnownHostsServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE, path);
        // Reject modified entries
        verifier.setModifiedServerKeyAcceptor((clientSession, remoteAddress, entry, expected, actual) -> false);

        KeyPair kp1 = CommonTestSupportUtils.generateKeyPair(KeyUtils.RSA_ALGORITHM, 1024);
        PublicKey serverKey1 = kp1.getPublic();

        SocketAddress address1 = new SshdSocketAddress(HASHED_HOST, port1);
        boolean accepted1 = invokeVerifier(verifier, address1, serverKey1);
        assertTrue("Accepted on port=" + port1 + " ?", accepted1);

        KeyPair kp2 = useSameKey ? kp1 : CommonTestSupportUtils.generateKeyPair(KeyUtils.RSA_ALGORITHM, 1024);
        PublicKey serverKey2 = kp2.getPublic();

        SocketAddress address2 = new SshdSocketAddress(HASHED_HOST, port2);
        boolean accepted2 = invokeVerifier(verifier, address2, serverKey2);
        assertTrue("Accepted on port=" + port2 + " ?", accepted2);

        Map<SshdSocketAddress, List<KnownHostEntry>> updatedKeys = loadEntries(path);
        assertEquals("Mismatched total entries count", 2, updatedKeys.size());
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

    private boolean invokeVerifier(ServerKeyVerifier verifier, SocketAddress hostIdentity, PublicKey serverKey) {
        ClientSession session = Mockito.mock(ClientSession.class);
        Mockito.when(session.getConnectAddress()).thenReturn(hostIdentity);
        Mockito.when(session.toString()).thenReturn(getCurrentTestName() + "[" + hostIdentity + "]");
        return verifier.verifyServerKey(session, hostIdentity, serverKey);
    }

    private static Map<SshdSocketAddress, List<KnownHostEntry>> loadEntries(Path file) throws IOException {
        Collection<KnownHostEntry> entries = KnownHostEntry.readKnownHostEntries(file);
        if (GenericUtils.isEmpty(entries)) {
            return Collections.emptyMap();
        }

        Map<SshdSocketAddress, List<KnownHostEntry>> hostsMap = new TreeMap<>(SshdSocketAddress.BY_HOST_AND_PORT);
        for (KnownHostEntry entry : entries) {
            String line = entry.getConfigLine();
            outputDebugMessage("loadTestLines(%s) processing %s", file, line);
            // extract hosts
            int markerOffset = 0;
            if (line.startsWith("@")) {
                markerOffset = line.indexOf(' ') + 1;
            }
            int pos = line.indexOf(' ', markerOffset);
            String patterns = line.substring(markerOffset, pos);
            if (entry.getHashedEntry() != null) {
                hostsMap.computeIfAbsent(new SshdSocketAddress(HASHED_HOST, 0), k -> new ArrayList<>()).add(entry);
            } else {
                String[] addrs = GenericUtils.split(patterns, ',');
                for (String a : addrs) {
                    int port = 0;
                    if (a.charAt(0) == HostPatternsHolder.NON_STANDARD_PORT_PATTERN_ENCLOSURE_START_DELIM) {
                        pos = a.indexOf(HostPatternsHolder.NON_STANDARD_PORT_PATTERN_ENCLOSURE_END_DELIM, 1);
                        assertTrue("Missing non-standard port host pattern enclosure: " + a, pos > 0);

                        port = Integer.parseInt(a.substring(pos + 2));
                        a = a.substring(1, pos);
                    }
                    hostsMap.computeIfAbsent(new SshdSocketAddress(a, port), k -> new ArrayList<>()).add(entry);
                }
            }
        }

        return hostsMap;
    }
}
