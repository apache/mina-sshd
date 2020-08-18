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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Writer;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import org.apache.sshd.client.config.hosts.KnownHostEntry;
import org.apache.sshd.client.config.hosts.KnownHostHashValue;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.config.ConfigFileReaderSupport;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.ModifiableFileWatcher;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class KnownHostsServerKeyVerifier
        extends ModifiableFileWatcher
        implements ServerKeyVerifier, ModifiedServerKeyAcceptor {

    /**
     * Standard option used to indicate whether to use strict host key checking or not. Values may be
     * &quot;yes/no&quot;, &quot;true/false&quot; or &quot;on/off&quot;
     */
    public static final String STRICT_CHECKING_OPTION = "StrictHostKeyChecking";

    /**
     * Standard option used to indicate alternative known hosts file location
     */
    public static final String KNOWN_HOSTS_FILE_OPTION = "UserKnownHostsFile";

    /**
     * Represents an entry in the internal verifier's cache
     *
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    public static class HostEntryPair {
        private KnownHostEntry hostEntry;
        private PublicKey serverKey;

        public HostEntryPair() {
            super();
        }

        public HostEntryPair(KnownHostEntry entry, PublicKey key) {
            this.hostEntry = Objects.requireNonNull(entry, "No entry");
            this.serverKey = Objects.requireNonNull(key, "No key");
        }

        public KnownHostEntry getHostEntry() {
            return hostEntry;
        }

        public void setHostEntry(KnownHostEntry hostEntry) {
            this.hostEntry = hostEntry;
        }

        public PublicKey getServerKey() {
            return serverKey;
        }

        public void setServerKey(PublicKey serverKey) {
            this.serverKey = serverKey;
        }

        @Override
        public String toString() {
            return String.valueOf(getHostEntry());
        }
    }

    protected final Object updateLock = new Object();
    private final ServerKeyVerifier delegate;
    private final AtomicReference<Supplier<? extends Collection<HostEntryPair>>> keysSupplier
            = new AtomicReference<>(getKnownHostSupplier(null, getPath()));
    private ModifiedServerKeyAcceptor modKeyAcceptor;

    public KnownHostsServerKeyVerifier(ServerKeyVerifier delegate, Path file) {
        this(delegate, file, IoUtils.EMPTY_LINK_OPTIONS);
    }

    public KnownHostsServerKeyVerifier(ServerKeyVerifier delegate, Path file, LinkOption... options) {
        super(file, options);
        this.delegate = Objects.requireNonNull(delegate, "No delegate");
    }

    public ServerKeyVerifier getDelegateVerifier() {
        return delegate;
    }

    /**
     * @return The delegate {@link ModifiedServerKeyAcceptor} to consult if a server presents a modified key. If
     *         {@code null} then assumed to reject such a modification
     */
    public ModifiedServerKeyAcceptor getModifiedServerKeyAcceptor() {
        return modKeyAcceptor;
    }

    /**
     * @param acceptor The delegate {@link ModifiedServerKeyAcceptor} to consult if a server presents a modified key. If
     *                 {@code null} then assumed to reject such a modification
     */
    public void setModifiedServerKeyAcceptor(ModifiedServerKeyAcceptor acceptor) {
        modKeyAcceptor = acceptor;
    }

    @Override
    public boolean verifyServerKey(ClientSession clientSession, SocketAddress remoteAddress, PublicKey serverKey) {
        try {
            if (checkReloadRequired()) {
                Path file = getPath();
                if (exists()) {
                    updateReloadAttributes();
                    keysSupplier.set(GenericUtils.memoizeLock(getKnownHostSupplier(clientSession, file)));
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("verifyServerKey({})[{}] missing known hosts file {}",
                                clientSession, remoteAddress, file);
                    }
                    keysSupplier.set(GenericUtils.memoizeLock(Collections::emptyList));
                }
            }
        } catch (Throwable t) {
            return acceptIncompleteHostKeys(clientSession, remoteAddress, serverKey, t);
        }

        Collection<HostEntryPair> knownHosts = keysSupplier.get().get();

        return acceptKnownHostEntries(clientSession, remoteAddress, serverKey, knownHosts);
    }

    protected Supplier<Collection<HostEntryPair>> getKnownHostSupplier(ClientSession clientSession, Path file) {
        return () -> {
            try {
                return reloadKnownHosts(clientSession, file);
            } catch (Exception e) {
                log.warn("verifyServerKey({}) Could not reload known hosts file {}",
                        clientSession, file, e);
                return Collections.emptyList();
            }
        };
    }

    protected void setLoadedHostsEntries(Collection<HostEntryPair> keys) {
        keysSupplier.set(() -> keys);
    }

    /**
     * @param  session                  The {@link ClientSession} that triggered this request
     * @param  file                     The {@link Path} to reload from
     * @return                          A {@link List} of the loaded {@link HostEntryPair}s - may be {@code null}/empty
     * @throws IOException              If failed to parse the file
     * @throws GeneralSecurityException If failed to resolve the encoded public keys
     */
    protected List<HostEntryPair> reloadKnownHosts(ClientSession session, Path file)
            throws IOException, GeneralSecurityException {
        Collection<KnownHostEntry> entries = KnownHostEntry.readKnownHostEntries(file);
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("reloadKnownHosts({}) loaded {} entries", file, entries.size());
        }
        updateReloadAttributes();

        if (GenericUtils.isEmpty(entries)) {
            return Collections.emptyList();
        }

        List<HostEntryPair> keys = new ArrayList<>(entries.size());
        PublicKeyEntryResolver resolver = getFallbackPublicKeyEntryResolver();
        for (KnownHostEntry entry : entries) {
            try {
                PublicKey key = resolveHostKey(session, entry, resolver);
                if (key != null) {
                    keys.add(new HostEntryPair(entry, key));
                }
            } catch (Throwable t) {
                warn("reloadKnownHosts({}) failed ({}) to load key of {}: {}",
                        file, t.getClass().getSimpleName(), entry, t.getMessage(), t);
            }
        }

        return keys;
    }

    /**
     * Recover the associated public key from a known host entry
     *
     * @param  session                  The {@link ClientSession} that triggered this request
     * @param  entry                    The {@link KnownHostEntry} - ignored if {@code null}
     * @param  resolver                 The {@link PublicKeyEntryResolver} to use if immediate - decoding does not work
     *                                  - ignored if {@code null}
     * @return                          The extracted {@link PublicKey} - {@code null} if none
     * @throws IOException              If failed to decode the key
     * @throws GeneralSecurityException If failed to generate the key
     * @see                             #getFallbackPublicKeyEntryResolver()
     * @see                             AuthorizedKeyEntry#resolvePublicKey(SessionContext, PublicKeyEntryResolver)
     */
    protected PublicKey resolveHostKey(
            ClientSession session, KnownHostEntry entry, PublicKeyEntryResolver resolver)
            throws IOException, GeneralSecurityException {
        if (entry == null) {
            return null;
        }

        AuthorizedKeyEntry authEntry = ValidateUtils.checkNotNull(entry.getKeyEntry(), "No key extracted from %s", entry);
        PublicKey key = authEntry.resolvePublicKey(session, resolver);
        if (log.isDebugEnabled()) {
            log.debug("resolveHostKey({}) loaded {}-{}", entry, KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key));
        }

        return key;
    }

    protected PublicKeyEntryResolver getFallbackPublicKeyEntryResolver() {
        return PublicKeyEntryResolver.IGNORING;
    }

    protected boolean acceptKnownHostEntries(
            ClientSession clientSession, SocketAddress remoteAddress, PublicKey serverKey,
            Collection<HostEntryPair> knownHosts) {
        // TODO allow for several candidates and check if ANY of them matches the key and has 'revoked' marker
        HostEntryPair match = findKnownHostEntry(clientSession, remoteAddress, knownHosts);
        if (match == null) {
            return acceptUnknownHostKey(clientSession, remoteAddress, serverKey);
        }

        KnownHostEntry entry = match.getHostEntry();
        PublicKey expected = match.getServerKey();
        if (KeyUtils.compareKeys(expected, serverKey)) {
            return acceptKnownHostEntry(clientSession, remoteAddress, serverKey, entry);
        }

        try {
            if (!acceptModifiedServerKey(clientSession, remoteAddress, entry, expected, serverKey)) {
                return false;
            }
        } catch (Throwable t) {
            warn("acceptKnownHostEntries({})[{}] failed ({}) to accept modified server key: {}",
                    clientSession, remoteAddress, t.getClass().getSimpleName(), t.getMessage(), t);
            return false;
        }

        Path file = getPath();
        try {
            updateModifiedServerKey(clientSession, remoteAddress, match, serverKey, file, knownHosts);
        } catch (Throwable t) {
            handleModifiedServerKeyUpdateFailure(clientSession, remoteAddress, match, serverKey, file, knownHosts, t);
        }

        return true;
    }

    /**
     * Invoked if a matching host entry was found, but the key did not match and
     * {@link #acceptModifiedServerKey(ClientSession, SocketAddress, KnownHostEntry, PublicKey, PublicKey)} returned
     * {@code true}. By default it locates the line to be updated and updates only its key data, marking the file for
     * reload on next verification just to be on the safe side.
     *
     * @param  clientSession The {@link ClientSession}
     * @param  remoteAddress The remote host address
     * @param  match         The {@link HostEntryPair} whose key does not match
     * @param  actual        The presented server {@link PublicKey} to be updated
     * @param  file          The file {@link Path} to be updated
     * @param  knownHosts    The currently loaded entries
     * @throws Exception     If failed to update the file - <B>Note:</B> this may mean the file is now corrupted
     * @see                  #handleModifiedServerKeyUpdateFailure(ClientSession, SocketAddress, HostEntryPair,
     *                       PublicKey, Path, Collection, Throwable)
     * @see                  #prepareModifiedServerKeyLine(ClientSession, SocketAddress, KnownHostEntry, String,
     *                       PublicKey, PublicKey)
     */
    protected void updateModifiedServerKey(
            ClientSession clientSession, SocketAddress remoteAddress, HostEntryPair match, PublicKey actual,
            Path file, Collection<HostEntryPair> knownHosts)
            throws Exception {
        KnownHostEntry entry = match.getHostEntry();
        String matchLine = ValidateUtils.checkNotNullAndNotEmpty(entry.getConfigLine(), "No entry config line");
        String newLine = prepareModifiedServerKeyLine(
                clientSession, remoteAddress, entry, matchLine, match.getServerKey(), actual);
        if (GenericUtils.isEmpty(newLine)) {
            if (log.isDebugEnabled()) {
                log.debug("updateModifiedServerKey({})[{}] no replacement generated for {}",
                        clientSession, remoteAddress, matchLine);
            }
            return;
        }

        if (matchLine.equals(newLine)) {
            if (log.isDebugEnabled()) {
                log.debug("updateModifiedServerKey({})[{}] unmodified updated line for {}",
                        clientSession, remoteAddress, matchLine);
            }
            return;
        }

        List<String> lines = new ArrayList<>();
        synchronized (updateLock) {
            int matchingIndex = -1; // read all lines but replace the updated one
            try (BufferedReader rdr = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                for (String line = rdr.readLine(); line != null; line = rdr.readLine()) {
                    // skip if already replaced the original line
                    if (matchingIndex >= 0) {
                        lines.add(line);
                        continue;
                    }
                    line = GenericUtils.trimToEmpty(line);
                    if (GenericUtils.isEmpty(line)) {
                        lines.add(line);
                        continue;
                    }

                    int pos = line.indexOf(ConfigFileReaderSupport.COMMENT_CHAR);
                    if (pos == 0) {
                        lines.add(line);
                        continue;
                    }

                    if (pos > 0) {
                        line = line.substring(0, pos);
                        line = line.trim();
                    }

                    if (!matchLine.equals(line)) {
                        lines.add(line);
                        continue;
                    }

                    lines.add(newLine);
                    matchingIndex = lines.size();
                }
            }

            ValidateUtils.checkTrue(matchingIndex >= 0, "No match found for line=%s", matchLine);

            try (Writer w = Files.newBufferedWriter(file, StandardCharsets.UTF_8)) {
                for (String l : lines) {
                    w.append(l).append(IoUtils.EOL);
                }
            }

            synchronized (match) {
                match.setServerKey(actual);
                entry.setConfigLine(newLine);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("updateModifiedServerKey({}) replaced '{}' with '{}'", file, matchLine, newLine);
        }
        resetReloadAttributes(); // force reload on next verification
    }

    /**
     * Invoked by
     * {@link #updateModifiedServerKey(ClientSession, SocketAddress, HostEntryPair, PublicKey, Path, Collection)} in
     * order to prepare the replacement - by default it replaces the key part with the new one
     *
     * @param  clientSession The {@link ClientSession}
     * @param  remoteAddress The remote host address
     * @param  entry         The {@link KnownHostEntry}
     * @param  curLine       The current entry line data
     * @param  expected      The expected {@link PublicKey}
     * @param  actual        The present key to be update
     * @return               The updated line - ignored if {@code null}/empty or same as original one
     * @throws Exception     if failed to prepare the line
     */
    protected String prepareModifiedServerKeyLine(
            ClientSession clientSession, SocketAddress remoteAddress, KnownHostEntry entry,
            String curLine, PublicKey expected, PublicKey actual)
            throws Exception {
        if ((entry == null) || GenericUtils.isEmpty(curLine)) {
            return curLine; // just to be on the safe side
        }

        int pos = curLine.indexOf(' ');
        if (curLine.charAt(0) == KnownHostEntry.MARKER_INDICATOR) {
            // skip marker till next token
            for (pos++; pos < curLine.length(); pos++) {
                if (curLine.charAt(pos) != ' ') {
                    break;
                }
            }

            pos = (pos < curLine.length()) ? curLine.indexOf(' ', pos) : -1;
        }

        ValidateUtils.checkTrue((pos > 0) && (pos < (curLine.length() - 1)), "Missing encoded key in line=%s", curLine);
        StringBuilder sb = new StringBuilder(curLine.length());
        sb.append(curLine.substring(0, pos)); // copy the marker/patterns as-is
        PublicKeyEntry.appendPublicKeyEntry(sb.append(' '), actual);
        return sb.toString();
    }

    /**
     * Invoked if {@code #updateModifiedServerKey(ClientSession, SocketAddress, HostEntryPair, PublicKey, Path)} throws
     * an exception. This may mean the file is corrupted, but it can be recovered from the known hosts that are being
     * provided. By default, it only logs a warning and does not attempt to recover the file
     *
     * @param clientSession The {@link ClientSession}
     * @param remoteAddress The remote host address
     * @param match         The {@link HostEntryPair} whose key does not match
     * @param serverKey     The presented server {@link PublicKey} to be updated
     * @param file          The file {@link Path} to be updated
     * @param knownHosts    The currently cached entries (may be {@code null}/empty)
     * @param reason        The failure reason
     */
    protected void handleModifiedServerKeyUpdateFailure(
            ClientSession clientSession, SocketAddress remoteAddress, HostEntryPair match,
            PublicKey serverKey, Path file, Collection<HostEntryPair> knownHosts, Throwable reason) {
        // NOTE !!! this may mean the file is corrupted, but it can be recovered from the known hosts
        warn("acceptKnownHostEntries({})[{}] failed ({}) to update modified server key of {}: {}",
                clientSession, remoteAddress, reason.getClass().getSimpleName(), match, reason.getMessage(), reason);
    }

    /**
     * Invoked <U>after</U> known host entry located and keys match - by default checks that entry has not been revoked
     *
     * @param  clientSession The {@link ClientSession}
     * @param  remoteAddress The remote host address
     * @param  serverKey     The presented server {@link PublicKey}
     * @param  entry         The {@link KnownHostEntry} value - if {@code null} then no known matching host entry was
     *                       found - default will call
     *                       {@link #acceptUnknownHostKey(ClientSession, SocketAddress, PublicKey)}
     * @return               {@code true} if OK to accept the server
     */
    protected boolean acceptKnownHostEntry(
            ClientSession clientSession, SocketAddress remoteAddress, PublicKey serverKey, KnownHostEntry entry) {
        if (entry == null) { // not really expected, but manage it
            return acceptUnknownHostKey(clientSession, remoteAddress, serverKey);
        }

        if ("revoked".equals(entry.getMarker())) {
            log.debug("acceptKnownHostEntry({})[{}] key={}-{} marked as {}",
                    clientSession, remoteAddress, KeyUtils.getKeyType(serverKey), KeyUtils.getFingerPrint(serverKey),
                    entry.getMarker());
            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("acceptKnownHostEntry({})[{}] matched key={}-{}",
                    clientSession, remoteAddress, KeyUtils.getKeyType(serverKey), KeyUtils.getFingerPrint(serverKey));
        }
        return true;
    }

    protected HostEntryPair findKnownHostEntry(
            ClientSession clientSession, SocketAddress remoteAddress, Collection<HostEntryPair> knownHosts) {
        if (GenericUtils.isEmpty(knownHosts)) {
            return null;
        }

        Collection<SshdSocketAddress> candidates = resolveHostNetworkIdentities(clientSession, remoteAddress);
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("findKnownHostEntry({})[{}] host network identities: {}",
                    clientSession, remoteAddress, candidates);
        }

        if (GenericUtils.isEmpty(candidates)) {
            return null;
        }

        for (HostEntryPair match : knownHosts) {
            KnownHostEntry entry = match.getHostEntry();
            for (SshdSocketAddress host : candidates) {
                try {
                    if (entry.isHostMatch(host.getHostName(), host.getPort())) {
                        if (debugEnabled) {
                            log.debug("findKnownHostEntry({})[{}] matched host={} for entry={}",
                                    clientSession, remoteAddress, host, entry);
                        }
                        return match;
                    }
                } catch (RuntimeException | Error e) {
                    warn("findKnownHostEntry({})[{}] failed ({}) to check host={} for entry={}: {}",
                            clientSession, remoteAddress, e.getClass().getSimpleName(),
                            host, entry.getConfigLine(), e.getMessage(), e);
                }
            }
        }

        return null; // no match found
    }

    /**
     * Called if failed to reload known hosts - by default invokes
     * {@link #acceptUnknownHostKey(ClientSession, SocketAddress, PublicKey)}
     *
     * @param  clientSession The {@link ClientSession}
     * @param  remoteAddress The remote host address
     * @param  serverKey     The presented server {@link PublicKey}
     * @param  reason        The {@link Throwable} that indicates the reload failure
     * @return               {@code true} if accept the server key anyway
     * @see                  #acceptUnknownHostKey(ClientSession, SocketAddress, PublicKey)
     */
    protected boolean acceptIncompleteHostKeys(
            ClientSession clientSession, SocketAddress remoteAddress, PublicKey serverKey, Throwable reason) {
        warn("Failed ({}) to reload server keys from {}: {}",
                reason.getClass().getSimpleName(), getPath(), reason.getMessage(), reason);
        return acceptUnknownHostKey(clientSession, remoteAddress, serverKey);
    }

    /**
     * Invoked if none of the known hosts matches the current one - by default invokes the delegate. If the delegate
     * accepts the key, then it is <U>appended</U> to the currently monitored entries and the file is updated
     *
     * @param  clientSession The {@link ClientSession}
     * @param  remoteAddress The remote host address
     * @param  serverKey     The presented server {@link PublicKey}
     * @return               {@code true} if accept the server key
     * @see                  #updateKnownHostsFile(ClientSession, SocketAddress, PublicKey, Path, Collection)
     * @see                  #handleKnownHostsFileUpdateFailure(ClientSession, SocketAddress, PublicKey, Path,
     *                       Collection, Throwable)
     */
    protected boolean acceptUnknownHostKey(ClientSession clientSession, SocketAddress remoteAddress, PublicKey serverKey) {
        if (log.isDebugEnabled()) {
            log.debug("acceptUnknownHostKey({}) host={}, key={}",
                    clientSession, remoteAddress, KeyUtils.getFingerPrint(serverKey));
        }

        if (delegate.verifyServerKey(clientSession, remoteAddress, serverKey)) {
            Path file = getPath();
            Collection<HostEntryPair> keys = keysSupplier.get().get();
            try {
                updateKnownHostsFile(clientSession, remoteAddress, serverKey, file, keys);
            } catch (Throwable t) {
                handleKnownHostsFileUpdateFailure(clientSession, remoteAddress, serverKey, file, keys, t);
            }

            return true;
        }

        return false;
    }

    /**
     * Invoked when {@link #updateKnownHostsFile(ClientSession, SocketAddress, PublicKey, Path, Collection)} fails - by
     * default just issues a warning. <B>Note:</B> there is a chance that the file is now corrupted and cannot be
     * re-used, so we provide a way to recover it via overriding this method and using the cached entries to re-created
     * it.
     *
     * @param clientSession The {@link ClientSession}
     * @param remoteAddress The remote host address
     * @param serverKey     The server {@link PublicKey} that was attempted to update
     * @param file          The file {@link Path} to be updated
     * @param knownHosts    The currently known entries (may be {@code null}/empty
     * @param reason        The failure reason
     */
    protected void handleKnownHostsFileUpdateFailure(
            ClientSession clientSession, SocketAddress remoteAddress, PublicKey serverKey,
            Path file, Collection<HostEntryPair> knownHosts, Throwable reason) {
        warn("handleKnownHostsFileUpdateFailure({})[{}] failed ({}) to update key={}-{} in {}: {}",
                clientSession, remoteAddress, reason.getClass().getSimpleName(),
                KeyUtils.getKeyType(serverKey), KeyUtils.getFingerPrint(serverKey),
                file, reason.getMessage(), reason);
    }

    /**
     * Invoked if a new previously unknown host key has been accepted - by default appends a new entry at the end of the
     * currently monitored known hosts file
     *
     * @param  clientSession The {@link ClientSession}
     * @param  remoteAddress The remote host address
     * @param  serverKey     The server {@link PublicKey} that to update
     * @param  file          The file {@link Path} to be updated
     * @param  knownHosts    The currently cached entries (may be {@code null}/empty)
     * @return               The generated {@link KnownHostEntry} or {@code null} if nothing updated. If anything
     *                       updated then the file will be re-loaded on next verification regardless of which server is
     *                       verified
     * @throws Exception     If failed to update the file - <B>Note:</B> in this case the file may be corrupted so
     *                       {@link #handleKnownHostsFileUpdateFailure(ClientSession, SocketAddress, PublicKey, Path, Collection, Throwable)}
     *                       will be called in order to enable recovery of its data
     * @see                  #resetReloadAttributes()
     */
    protected KnownHostEntry updateKnownHostsFile(
            ClientSession clientSession, SocketAddress remoteAddress, PublicKey serverKey,
            Path file, Collection<HostEntryPair> knownHosts)
            throws Exception {
        KnownHostEntry entry = prepareKnownHostEntry(clientSession, remoteAddress, serverKey);
        if (entry == null) {
            if (log.isDebugEnabled()) {
                log.debug("updateKnownHostsFile({})[{}] no entry generated for key={}",
                        clientSession, remoteAddress, KeyUtils.getFingerPrint(serverKey));
            }

            return null;
        }

        String line = entry.getConfigLine();
        byte[] lineData = line.getBytes(StandardCharsets.UTF_8);
        boolean reuseExisting = Files.exists(file) && (Files.size(file) > 0);
        byte[] eolBytes = IoUtils.getEOLBytes();
        synchronized (updateLock) {
            try (OutputStream output = reuseExisting
                    ? Files.newOutputStream(file, StandardOpenOption.APPEND)
                    : Files.newOutputStream(file)) {
                if (reuseExisting) {
                    output.write(eolBytes); // separate from previous lines
                }

                output.write(lineData);
                output.write(eolBytes); // add another separator for trailing lines - in case regular SSH client appends
                                       // to it
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("updateKnownHostsFile({}) updated: {}", file, entry);
        }
        resetReloadAttributes(); // force reload on next verification
        return entry;
    }

    /**
     * Invoked by {@link #updateKnownHostsFile(ClientSession, SocketAddress, PublicKey, Path, Collection)} in order to
     * generate the host entry to be written
     *
     * @param  clientSession The {@link ClientSession}
     * @param  remoteAddress The remote host address
     * @param  serverKey     The server {@link PublicKey} that was attempted to update
     * @return               The {@link KnownHostEntry} to use - if {@code null} then entry is not updated in the file
     * @throws Exception     If failed to generate the entry - e.g. failed to hash
     * @see                  #resolveHostNetworkIdentities(ClientSession, SocketAddress)
     * @see                  KnownHostEntry#getConfigLine()
     */
    protected KnownHostEntry prepareKnownHostEntry(
            ClientSession clientSession, SocketAddress remoteAddress, PublicKey serverKey)
            throws Exception {
        Collection<SshdSocketAddress> patterns = resolveHostNetworkIdentities(clientSession, remoteAddress);
        if (GenericUtils.isEmpty(patterns)) {
            return null;
        }

        StringBuilder sb = new StringBuilder(Byte.MAX_VALUE);
        Random rnd = null;
        for (SshdSocketAddress hostIdentity : patterns) {
            if (sb.length() > 0) {
                sb.append(',');
            }

            NamedFactory<Mac> digester = getHostValueDigester(clientSession, remoteAddress, hostIdentity);
            if (digester != null) {
                if (rnd == null) {
                    FactoryManager manager = Objects.requireNonNull(clientSession.getFactoryManager(), "No factory manager");
                    Factory<? extends Random> factory = Objects.requireNonNull(manager.getRandomFactory(), "No random factory");
                    rnd = Objects.requireNonNull(factory.create(), "No randomizer created");
                }

                Mac mac = digester.create();
                int blockSize = mac.getDefaultBlockSize();
                byte[] salt = new byte[blockSize];
                rnd.fill(salt);

                byte[] digestValue = KnownHostHashValue.calculateHashValue(
                        hostIdentity.getHostName(), hostIdentity.getPort(), mac, salt);
                KnownHostHashValue.append(sb, digester, salt, digestValue);
            } else {
                KnownHostHashValue.appendHostPattern(sb, hostIdentity.getHostName(), hostIdentity.getPort());
            }
        }

        PublicKeyEntry.appendPublicKeyEntry(sb.append(' '), serverKey);
        return KnownHostEntry.parseKnownHostEntry(sb.toString());
    }

    /**
     * Invoked by {@link #prepareKnownHostEntry(ClientSession, SocketAddress, PublicKey)} in order to query whether to
     * use a hashed value instead of a plain one for the written host name/address - default returns {@code null} -
     * i.e., no hashing
     *
     * @param  clientSession The {@link ClientSession}
     * @param  remoteAddress The remote host address
     * @param  hostIdentity  The entry's host name/address
     * @return               The digester {@link NamedFactory} - {@code null} if no hashing is to be made
     */
    protected NamedFactory<Mac> getHostValueDigester(
            ClientSession clientSession, SocketAddress remoteAddress, SshdSocketAddress hostIdentity) {
        return null;
    }

    /**
     * Retrieves the host identities to be used when matching or updating an entry for it - by default returns the
     * reported remote address and the original connection target host name/address (if same, then only one value is
     * returned)
     *
     * @param  clientSession The {@link ClientSession}
     * @param  remoteAddress The remote host address
     * @return               A {@link Collection} of the {@code InetSocketAddress}-es to use - if {@code null}/empty
     *                       then ignored (i.e., no matching is done or no entry is generated)
     * @see                  ClientSession#getConnectAddress()
     * @see                  SshdSocketAddress#toSshdSocketAddress(SocketAddress)
     */
    protected Collection<SshdSocketAddress> resolveHostNetworkIdentities(
            ClientSession clientSession, SocketAddress remoteAddress) {
        /*
         * NOTE !!! we do not resolve the fully-qualified name to avoid long DNS timeouts. Instead we use the reported
         * peer address and the original connection target host
         */
        Collection<SshdSocketAddress> candidates = new TreeSet<>(SshdSocketAddress.BY_HOST_AND_PORT);
        candidates.add(SshdSocketAddress.toSshdSocketAddress(remoteAddress));
        SocketAddress connectAddress = clientSession.getConnectAddress();
        candidates.add(SshdSocketAddress.toSshdSocketAddress(connectAddress));
        return candidates;
    }

    @Override
    public boolean acceptModifiedServerKey(
            ClientSession clientSession, SocketAddress remoteAddress,
            KnownHostEntry entry, PublicKey expected, PublicKey actual)
            throws Exception {
        ModifiedServerKeyAcceptor acceptor = getModifiedServerKeyAcceptor();
        if (acceptor != null) {
            return acceptor.acceptModifiedServerKey(clientSession, remoteAddress, entry, expected, actual);
        }

        log.warn("acceptModifiedServerKey({}) mismatched keys presented by {} for entry={}: expected={}-{}, actual={}-{}",
                clientSession, remoteAddress, entry,
                KeyUtils.getKeyType(expected), KeyUtils.getFingerPrint(expected),
                KeyUtils.getKeyType(actual), KeyUtils.getFingerPrint(actual));
        return false;
    }
}
