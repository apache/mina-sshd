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

package org.apache.sshd.client.config.hosts;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StreamCorruptedException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.config.ConfigFileReaderSupport;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.NoCloseInputStream;
import org.apache.sshd.common.util.io.NoCloseReader;

/**
 * Contains a representation of an entry in the <code>known_hosts</code> file
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="http://www.manpagez.com/man/8/sshd/">sshd(8) man page</A>
 */
public class KnownHostEntry extends HostPatternsHolder {
    /**
     * Character that denotes that start of a marker
     */
    public static final char MARKER_INDICATOR = '@';

    /**
     * Standard OpenSSH config file name
     */
    public static final String STD_HOSTS_FILENAME = "known_hosts";

    private static final class LazyDefaultConfigFileHolder {
        private static final Path HOSTS_FILE = PublicKeyEntry.getDefaultKeysFolderPath().resolve(STD_HOSTS_FILENAME);

        private LazyDefaultConfigFileHolder() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }

    private String line;
    private String marker;
    private AuthorizedKeyEntry keyEntry;
    private KnownHostHashValue hashedEntry;

    public KnownHostEntry() {
        super();
    }

    /**
     * @param line The original line from which this entry was created
     */
    public KnownHostEntry(String line) {
        this.line = line;
    }

    /**
     * @return The original line from which this entry was created
     */
    public String getConfigLine() {
        return line;
    }

    public void setConfigLine(String line) {
        this.line = line;
    }

    public String getMarker() {
        return marker;
    }

    public void setMarker(String marker) {
        this.marker = marker;
    }

    public AuthorizedKeyEntry getKeyEntry() {
        return keyEntry;
    }

    public void setKeyEntry(AuthorizedKeyEntry keyEntry) {
        this.keyEntry = keyEntry;
    }

    public KnownHostHashValue getHashedEntry() {
        return hashedEntry;
    }

    public void setHashedEntry(KnownHostHashValue hashedEntry) {
        this.hashedEntry = hashedEntry;
    }

    @Override
    public boolean isHostMatch(String host, int port) {
        if (super.isHostMatch(host, port)) {
            return true;
        }

        KnownHostHashValue hash = getHashedEntry();
        return (hash != null) && hash.isHostMatch(host, port);
    }

    @Override
    public String toString() {
        return getConfigLine();
    }

    /**
     * @return The default {@link Path} location of the OpenSSH known hosts file
     */
    @SuppressWarnings("synthetic-access")
    public static Path getDefaultKnownHostsFile() {
        return LazyDefaultConfigFileHolder.HOSTS_FILE;
    }

    public static List<KnownHostEntry> readKnownHostEntries(Path path, OpenOption... options) throws IOException {
        try (InputStream input = Files.newInputStream(path, options)) {
            return readKnownHostEntries(input, true);
        }
    }

    public static List<KnownHostEntry> readKnownHostEntries(URL url) throws IOException {
        try (InputStream input = url.openStream()) {
            return readKnownHostEntries(input, true);
        }
    }

    public static List<KnownHostEntry> readKnownHostEntries(InputStream inStream, boolean okToClose) throws IOException {
        try (Reader reader
                = new InputStreamReader(NoCloseInputStream.resolveInputStream(inStream, okToClose), StandardCharsets.UTF_8)) {
            return readKnownHostEntries(reader, true);
        }
    }

    public static List<KnownHostEntry> readKnownHostEntries(Reader rdr, boolean okToClose) throws IOException {
        try (BufferedReader buf = new BufferedReader(NoCloseReader.resolveReader(rdr, okToClose))) {
            return readKnownHostEntries(buf);
        }
    }

    /**
     * Reads configuration entries
     *
     * @param  rdr         The {@link BufferedReader} to use
     * @return             The {@link List} of read {@link KnownHostEntry}-ies
     * @throws IOException If failed to parse the read configuration
     */
    public static List<KnownHostEntry> readKnownHostEntries(BufferedReader rdr) throws IOException {
        List<KnownHostEntry> entries = null;

        int lineNumber = 1;
        for (String line = rdr.readLine(); line != null; line = rdr.readLine(), lineNumber++) {
            line = GenericUtils.trimToEmpty(line);
            if (GenericUtils.isEmpty(line)) {
                continue;
            }

            int pos = line.indexOf(ConfigFileReaderSupport.COMMENT_CHAR);
            if (pos == 0) {
                continue;
            }

            if (pos > 0) {
                line = line.substring(0, pos);
                line = line.trim();
            }

            try {
                KnownHostEntry entry = parseKnownHostEntry(line);
                if (entry == null) {
                    continue;
                }

                if (entries == null) {
                    entries = new ArrayList<>();
                }
                entries.add(entry);
            } catch (RuntimeException | Error e) { // TODO consider consulting a user callback
                throw new StreamCorruptedException(
                        "Failed (" + e.getClass().getSimpleName() + ")" + " to parse line #" + lineNumber + " '" + line + "': "
                                                   + e.getMessage());
            }
        }

        if (entries == null) {
            return Collections.emptyList();
        } else {
            return entries;
        }
    }

    public static KnownHostEntry parseKnownHostEntry(String line) {
        return parseKnownHostEntry(GenericUtils.isEmpty(line) ? null : new KnownHostEntry(), line);
    }

    public static <E extends KnownHostEntry> E parseKnownHostEntry(E entry, String data) {
        String line = GenericUtils.replaceWhitespaceAndTrim(data);
        if (GenericUtils.isEmpty(line) || (line.charAt(0) == PublicKeyEntry.COMMENT_CHAR)) {
            return entry;
        }

        entry.setConfigLine(line);

        if (line.charAt(0) == MARKER_INDICATOR) {
            int pos = line.indexOf(' ');
            ValidateUtils.checkTrue(pos > 0, "Missing marker name end delimiter in line=%s", data);
            ValidateUtils.checkTrue(pos > 1, "No marker name after indicator in line=%s", data);
            entry.setMarker(line.substring(1, pos));
            line = line.substring(pos + 1).trim();
        } else {
            entry.setMarker(null);
        }

        int pos = line.indexOf(' ');
        ValidateUtils.checkTrue(pos > 0, "Missing host patterns end delimiter in line=%s", data);
        String hostPattern = line.substring(0, pos);
        line = line.substring(pos + 1).trim();

        if (hostPattern.charAt(0) == KnownHostHashValue.HASHED_HOST_DELIMITER) {
            KnownHostHashValue hash = ValidateUtils.checkNotNull(KnownHostHashValue.parse(hostPattern),
                    "Failed to extract host hash value from line=%s", data);
            entry.setHashedEntry(hash);
            entry.setPatterns(null);
        } else {
            entry.setHashedEntry(null);
            entry.setPatterns(parsePatterns(GenericUtils.split(hostPattern, ',')));
        }

        AuthorizedKeyEntry key = ValidateUtils.checkNotNull(AuthorizedKeyEntry.parseAuthorizedKeyEntry(line),
                "No valid key entry recovered from line=%s", data);
        entry.setKeyEntry(key);
        return entry;
    }
}
