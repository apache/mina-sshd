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
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.StreamCorruptedException;
import java.io.Writer;
import java.net.InetAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.TreeMap;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.auth.MutableUserHolder;
import org.apache.sshd.common.config.ConfigFileReaderSupport;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.PathUtils;
import org.apache.sshd.common.util.io.input.NoCloseInputStream;
import org.apache.sshd.common.util.io.input.NoCloseReader;
import org.apache.sshd.common.util.io.output.NoCloseOutputStream;

/**
 * Represents an entry in the client's configuration file as defined by the
 * <A HREF="https://linux.die.net/man/5/ssh_config">ssh_config</A> configuration file format
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="https://www.cyberciti.biz/faq/create-ssh-config-file-on-linux-unix/">OpenSSH Config File
 *         Examples</A>
 */
public class HostConfigEntry extends HostPatternsHolder implements MutableUserHolder {
    /**
     * Standard OpenSSH config file name
     */
    public static final String STD_CONFIG_FILENAME = "config";

    public static final String HOST_CONFIG_PROP = "Host";
    public static final String MATCH_CONFIG_PROP = "Match";  // currently not handled
    public static final String HOST_NAME_CONFIG_PROP = "HostName";
    public static final String PORT_CONFIG_PROP = ConfigFileReaderSupport.PORT_CONFIG_PROP;
    public static final String USER_CONFIG_PROP = "User";
    public static final String PROXY_JUMP_CONFIG_PROP = "ProxyJump";
    public static final String IDENTITY_FILE_CONFIG_PROP = "IdentityFile";
    public static final String CERTIFICATE_FILE_CONFIG_PROP = "CertificateFile";  // currently not handled
    /**
     * Use only the identities specified in the host entry (if any)
     */
    public static final String EXCLUSIVE_IDENTITIES_CONFIG_PROP = "IdentitiesOnly";
    public static final boolean DEFAULT_EXCLUSIVE_IDENTITIES = false;

    /**
     * The IdentityAgent configuration. If not set in the {@link HostConfigEntry}, the value of this
     * {@link #getProperty(String) property} is {@code null}, which means that a default SSH agent is to be used, if it
     * is running. Other values defined by OpenSSH are:
     * <ul>
     * <dl>
     * <dt>none</dt>
     * <dd>No SHH agent is to be used at all, even if one is running.</dd>
     * <dt>SSH_AUTH_SOCK</dt>
     * <dd>The SSH agent listening on the Unix domain socket given by the environment variable {@code SSH_AUTH_SOCK}
     * shall be used. If the environment variable is not set, no SSH agent is used.</dd>
     * <dt><em>other</em></dt>
     * <dd>For OpenSSH, the value shall resolve to the file name of a Unix domain socket to use to connect to an SSH
     * agent.</dd>
     * </dl>
     */
    public static final String IDENTITY_AGENT = "IdentityAgent";

    /**
     * A case <U>insensitive</U> {@link NavigableSet} of the properties that receive special handling
     */
    public static final NavigableSet<String> EXPLICIT_PROPERTIES = Collections.unmodifiableNavigableSet(
            GenericUtils.asSortedSet(String.CASE_INSENSITIVE_ORDER,
                    HOST_CONFIG_PROP, HOST_NAME_CONFIG_PROP, PORT_CONFIG_PROP,
                    USER_CONFIG_PROP, IDENTITY_FILE_CONFIG_PROP, EXCLUSIVE_IDENTITIES_CONFIG_PROP));

    public static final String MULTI_VALUE_SEPARATORS = " ,";

    public static final char PATH_MACRO_CHAR = '%';
    public static final char LOCAL_HOME_MACRO = 'd';
    public static final char LOCAL_USER_MACRO = 'u';
    public static final char LOCAL_HOST_MACRO = 'l';
    public static final char REMOTE_HOST_MACRO = 'h';
    public static final char REMOTE_USER_MACRO = 'r';
    // Extra - not part of the standard
    public static final char REMOTE_PORT_MACRO = 'p';

    private static final class LazyDefaultConfigFileHolder {
        private static final Path CONFIG_FILE = PublicKeyEntry.getDefaultKeysFolderPath().resolve(STD_CONFIG_FILENAME);

        private LazyDefaultConfigFileHolder() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }

    // TODO: A better approach would be to only store "host" and the properties map. Accessors can read/write the properties map.
    // TODO: Map property key to generic object. Any code that calls getProperties() would need to be updated.
    protected String host;
    protected String hostName;
    protected int port;
    protected String username;
    protected String proxyJump;
    protected Boolean exclusiveIdentites;

    // TODO: OpenSSH ignores duplicates. Ignoring them here (via a set) would complicate keeping the map entry in sync.
    protected final Collection<String> identities = new ArrayList<>();
    protected final Map<String, String> properties = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    public HostConfigEntry() {
        super();
    }

    public HostConfigEntry(String pattern, String host, int port, String username) {
        this(pattern, host, port, username, null);
    }

    public HostConfigEntry(String pattern, String host, int port, String username, String proxyJump) {
        setHost(pattern);
        setHostName(host);
        setPort(port);
        setUsername(username);
        setProxyJump(proxyJump);
    }

    /**
     * Merges that into this via underride. That is, any value present in this entry takes precedence over the given
     * entry. Only this object is modified. The given entry remains unchanged.
     *
     * @param that The HostConfigEntry to merge.
     */
    public void collate(HostConfigEntry that) {
        if (hostName == null || hostName.isEmpty()) {
            hostName = that.hostName;  // It doesn't matter whether that host is defined or not, since ours is not.
        }

        if (port <= 0) {
            port = that.port;
        }

        if (username == null || username.isEmpty()) {
            username = that.username;
        }

        if (proxyJump == null || proxyJump.isEmpty()) {
            proxyJump = that.proxyJump;
        }

        if (exclusiveIdentites == null) {
            exclusiveIdentites = that.exclusiveIdentites;
        }

        identities.addAll(that.identities);

        for (Entry<String, String> e : that.properties.entrySet()) {
            String key = e.getKey();
            String value = e.getValue();
            if (properties.containsKey(key)) {
                if (key.equalsIgnoreCase(IDENTITY_FILE_CONFIG_PROP) || key.equalsIgnoreCase(CERTIFICATE_FILE_CONFIG_PROP)) {
                    properties.put(key, properties.get(key) + "," + value);
                }
                // else ignore, since our value takes precedence over that
            } else {  // key is not present in our properties
                properties.put(key, value);
            }
        }
    }

    /**
     * @return The <U>pattern(s)</U> represented by this entry
     */
    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
        setPatterns(parsePatterns(parseConfigValue(host)));
    }

    public void setHost(Collection<String> patterns) {
        this.host = GenericUtils.join(ValidateUtils.checkNotNullAndNotEmpty(patterns, "No patterns"), ',');
        setPatterns(parsePatterns(patterns));
    }

    /**
     * @return The effective host name to connect to if the pattern matches
     */
    public String getHostName() {
        return hostName;
    }

    public void setHostName(String hostName) {
        this.hostName = hostName;
        setProperty(HOST_NAME_CONFIG_PROP, hostName);
    }

    /**
     * @return A port override - if positive
     */
    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
        if (port <= 0) {
            properties.remove(PORT_CONFIG_PROP);
        } else {
            setProperty(PORT_CONFIG_PROP, String.valueOf(port));
        }
    }

    /**
     * @return A username override - if not {@code null}/empty
     */
    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public void setUsername(String username) {
        this.username = username;
        setProperty(USER_CONFIG_PROP, username);
    }

    /**
     * @return the host to use as a proxy
     */
    public String getProxyJump() {
        return proxyJump;
    }

    public void setProxyJump(String proxyJump) {
        this.proxyJump = proxyJump;
        setProperty(PROXY_JUMP_CONFIG_PROP, proxyJump);
    }

    /**
     * @return The current identities file paths - may be {@code null}/empty
     */
    public Collection<String> getIdentities() {
        return identities;
    }

    /**
     * @param path A {@link Path} to a file that contains an identity key - never {@code null}
     */
    public void addIdentity(Path path) {
        addIdentity(Objects.requireNonNull(path, "No path").toAbsolutePath().normalize().toString());
    }

    /**
     * Adds a path to an identity file
     *
     * @param id The identity path to add - never {@code null}
     */
    public void addIdentity(String id) {
        String path = ValidateUtils.hasContent(id, "No identity provided");
        identities.add(path);
        appendPropertyValue(IDENTITY_FILE_CONFIG_PROP, id);
    }

    public void setIdentities(Collection<String> identities) {
        this.identities.clear();
        properties.remove(IDENTITY_FILE_CONFIG_PROP);
        if (identities != null) {
            identities.forEach(this::addIdentity);
        }
    }

    /**
     * @return {@code true} if must use only the identities in this entry
     */
    public boolean isIdentitiesOnly() {
        return (exclusiveIdentites == null) ? DEFAULT_EXCLUSIVE_IDENTITIES : exclusiveIdentites;
    }

    public void setIdentitiesOnly(boolean identitiesOnly) {
        exclusiveIdentites = identitiesOnly;
        setProperty(EXCLUSIVE_IDENTITIES_CONFIG_PROP, Boolean.toString(identitiesOnly));
    }

    /**
     * @return A {@link Map} of extra properties that have been read - may be {@code null}/empty, or even contain some
     *         values that have been parsed and set as members of the entry (e.g., host, port, etc.). <B>Note:</B>
     *         multi-valued keys use a comma-separated list of values
     */
    public Map<String, String> getProperties() {
        return properties;
    }

    /**
     * @param  name Property name - never {@code null}/empty
     * @return      Property value or {@code null} if no such property
     * @see         #getProperty(String, String)
     */
    public String getProperty(String name) {
        return getProperty(name, null);
    }

    /**
     * @param  name         Property name - never {@code null}/empty
     * @param  defaultValue Default value to return if no such property
     * @return              The property value or the default one if no such property
     */
    public String getProperty(String name, String defaultValue) {
        String key = ValidateUtils.checkNotNullAndNotEmpty(name, "No property name");
        Map<String, String> props = getProperties();
        if (MapEntryUtils.isEmpty(props)) {
            return defaultValue;
        }

        String value = props.get(key);
        if (GenericUtils.isEmpty(value)) {
            return defaultValue;
        } else {
            return value;
        }
    }

    /**
     * @param name     Property name - never {@code null}/empty
     * @param valsList The available values for the property
     * @see            #HOST_NAME_CONFIG_PROP
     * @see            #PORT_CONFIG_PROP
     * @see            #USER_CONFIG_PROP
     * @see            #IDENTITY_FILE_CONFIG_PROP
     */
    public void processProperty(String name, Collection<String> valsList) {
        String key = ValidateUtils.checkNotNullAndNotEmpty(name, "No property name");
        String joinedValue = GenericUtils.join(valsList, ',');

        if (HOST_NAME_CONFIG_PROP.equalsIgnoreCase(key)) {
            ValidateUtils.checkTrue(GenericUtils.size(valsList) == 1, "Multiple target hosts N/A: %s", joinedValue);
            setHostName(joinedValue);
        } else if (PORT_CONFIG_PROP.equalsIgnoreCase(key)) {
            ValidateUtils.checkTrue(GenericUtils.size(valsList) == 1, "Multiple target ports N/A: %s", joinedValue);
            int newValue = Integer.parseInt(joinedValue);
            ValidateUtils.checkTrue(newValue > 0, "Bad new port value: %d", newValue);
            setPort(newValue);
        } else if (USER_CONFIG_PROP.equalsIgnoreCase(key)) {
            ValidateUtils.checkTrue(GenericUtils.size(valsList) == 1, "Multiple target users N/A: %s", joinedValue);
            setUsername(joinedValue);
        } else if (IDENTITY_FILE_CONFIG_PROP.equalsIgnoreCase(key)) {
            ValidateUtils.checkTrue(GenericUtils.size(valsList) > 0, "No identity files specified");
            for (String id : valsList) {
                addIdentity(id);
            }
        } else if (EXCLUSIVE_IDENTITIES_CONFIG_PROP.equalsIgnoreCase(key)) {
            setIdentitiesOnly(
                    ConfigFileReaderSupport.parseBooleanValue(
                            ValidateUtils.checkNotNullAndNotEmpty(joinedValue, "No identities option value")));
        } else if (PROXY_JUMP_CONFIG_PROP.equalsIgnoreCase(key)) {
            setProxyJump(joinedValue);
        } else if (CERTIFICATE_FILE_CONFIG_PROP.equalsIgnoreCase(key)) {
            appendPropertyValue(key, joinedValue);
        } else {
            properties.put(key, joinedValue);  // Default is to overwrite any previous value. Only identities
        }
    }

    /**
     * Appends a value using a <U>comma</U> to an existing one. If no previous value then same as calling
     * {@link #setProperty(String, String)}.
     *
     * @param  name  Property name - never {@code null}/empty
     * @param  value The value to be appended - ignored if {@code null}/empty
     * @return       The value <U>before</U> appending - {@code null} if no previous value
     */
    public String appendPropertyValue(String name, String value) {
        String key = ValidateUtils.checkNotNullAndNotEmpty(name, "No property name");
        String curVal = getProperty(key);
        if (GenericUtils.isEmpty(value)) {
            return curVal;
        }

        if (GenericUtils.isEmpty(curVal)) {
            return setProperty(key, value);
        }

        return setProperty(key, curVal + ',' + value);
    }

    /**
     * Sets / Replaces the property value
     *
     * @param  name  Property name - never {@code null}/empty
     * @param  value Property value - if {@code null}/empty then {@link #removeProperty(String)} is called
     * @return       The previous property value - {@code null} if no such name
     */
    public String setProperty(String name, String value) {
        if (GenericUtils.isEmpty(value)) {
            return removeProperty(name);
        }
        String key = ValidateUtils.checkNotNullAndNotEmpty(name, "No property name");
        return properties.put(key, value);
    }

    /**
     * @param  name Property name - never {@code null}/empty
     * @return      The removed property value - {@code null} if no such property name
     */
    public String removeProperty(String name) {
        String key = ValidateUtils.checkNotNullAndNotEmpty(name, "No property name");
        Map<String, String> props = getProperties();
        if (MapEntryUtils.isEmpty(props)) {
            return null;
        } else {
            return props.remove(key);
        }
    }

    /**
     * @param properties The properties to set - if {@code null} then an empty map is effectively set. <B>Note:</B> it
     *                   is highly recommended to use a <U>case insensitive</U> key mapper.
     */
    public void setProperties(Map<String, String> properties) {
        this.properties.clear();
        if (properties != null) {
            this.properties.putAll(properties);
        }
    }

    public <A extends Appendable> A append(A sb) throws IOException {
        sb.append(HOST_CONFIG_PROP).append(' ').append(ValidateUtils.checkNotNullAndNotEmpty(getHost(), "No host pattern"))
                .append(IoUtils.EOL);
        appendNonEmptyProperty(sb, HOST_NAME_CONFIG_PROP, getHostName());
        appendNonEmptyPort(sb, PORT_CONFIG_PROP, getPort());
        appendNonEmptyProperty(sb, USER_CONFIG_PROP, getUsername());
        appendNonEmptyValues(sb, IDENTITY_FILE_CONFIG_PROP, getIdentities());
        if (exclusiveIdentites != null) {
            appendNonEmptyProperty(sb, EXCLUSIVE_IDENTITIES_CONFIG_PROP,
                    ConfigFileReaderSupport.yesNoValueOf(exclusiveIdentites));
        }
        appendNonEmptyProperties(sb, getProperties());
        return sb;
    }

    @Override
    public String toString() {
        return getHost() + ": " + getUsername() + "@" + getHostName() + ":" + getPort();
    }

    /**
     * @param  <A>         The {@link Appendable} type
     * @param  sb          The target appender
     * @param  name        The property name - never {@code null}/empty
     * @param  port        The port value - ignored if non-positive
     * @return             The target appender after having appended (or not) the value
     * @throws IOException If failed to append the requested data
     * @see                #appendNonEmptyProperty(Appendable, String, Object)
     */
    public static <A extends Appendable> A appendNonEmptyPort(A sb, String name, int port) throws IOException {
        return appendNonEmptyProperty(sb, name, (port > 0) ? Integer.toString(port) : null);
    }

    /**
     * Appends the extra properties - while skipping the {@link #EXPLICIT_PROPERTIES} ones
     *
     * @param  <A>         The {@link Appendable} type
     * @param  sb          The target appender
     * @param  props       The {@link Map} of properties - ignored if {@code null}/empty
     * @return             The target appender after having appended (or not) the value
     * @throws IOException If failed to append the requested data
     * @see                #appendNonEmptyProperty(Appendable, String, Object)
     */
    public static <A extends Appendable> A appendNonEmptyProperties(A sb, Map<String, ?> props) throws IOException {
        if (MapEntryUtils.isEmpty(props)) {
            return sb;
        }

        // Cannot use forEach because of the IOException being thrown by appendNonEmptyProperty
        for (Map.Entry<String, ?> pe : props.entrySet()) {
            String name = pe.getKey();
            if (EXPLICIT_PROPERTIES.contains(name)) {
                continue;
            }

            appendNonEmptyProperty(sb, name, pe.getValue());
        }

        return sb;
    }

    /**
     * @param  <A>         The {@link Appendable} type
     * @param  sb          The target appender
     * @param  name        The property name - never {@code null}/empty
     * @param  value       The property value - ignored if {@code null}. <B>Note:</B> if the string representation of
     *                     the value contains any commas, they are assumed to indicate a multi-valued property which is
     *                     broken down to <U>individual</U> lines - one per value.
     * @return             The target appender after having appended (or not) the value
     * @throws IOException If failed to append the requested data
     * @see                #appendNonEmptyValues(Appendable, String, Object...)
     */
    public static <A extends Appendable> A appendNonEmptyProperty(A sb, String name, Object value) throws IOException {
        String s = Objects.toString(value, null);
        String[] vals = GenericUtils.split(s, ',');
        return appendNonEmptyValues(sb, name, (Object[]) vals);
    }

    /**
     * @param  <A>         The {@link Appendable} type
     * @param  sb          The target appender
     * @param  name        The property name - never {@code null}/empty
     * @param  values      The values to be added - one per line - ignored if {@code null}/empty
     * @return             The target appender after having appended (or not) the value
     * @throws IOException If failed to append the requested data
     * @see                #appendNonEmptyValues(Appendable, String, Collection)
     */
    public static <A extends Appendable> A appendNonEmptyValues(A sb, String name, Object... values) throws IOException {
        return appendNonEmptyValues(sb, name, GenericUtils.isEmpty(values) ? Collections.emptyList() : Arrays.asList(values));
    }

    /**
     * @param  <A>         The {@link Appendable} type
     * @param  sb          The target appender
     * @param  name        The property name - never {@code null}/empty
     * @param  values      The values to be added - one per line - ignored if {@code null}/empty
     * @return             The target appender after having appended (or not) the value
     * @throws IOException If failed to append the requested data
     */
    public static <A extends Appendable> A appendNonEmptyValues(A sb, String name, Collection<?> values) throws IOException {
        String k = ValidateUtils.checkNotNullAndNotEmpty(name, "No property name");
        if (GenericUtils.isEmpty(values)) {
            return sb;
        }

        for (Object v : values) {
            sb.append("    ").append(k).append(' ').append(Objects.toString(v)).append(IoUtils.EOL);
        }

        return sb;
    }

    /**
     * Locates all the matching entries for a give host name / address
     *
     * @param  host    The host name / address - ignored if {@code null}/empty
     * @param  entries The {@link HostConfigEntry}-ies to scan - ignored if {@code null}/empty
     * @return         A {@link List} of all the matching entries
     * @see            #isHostMatch(String, int)
     */
    public static List<HostConfigEntry> findMatchingEntries(String host, HostConfigEntry... entries) {
        if (GenericUtils.isEmpty(host) || GenericUtils.isEmpty(entries)) {
            return Collections.emptyList();
        } else {
            return findMatchingEntries(host, Arrays.asList(entries));
        }
    }

    /**
     * Locates all the matching entries for a give host name / address
     *
     * @param  host    The host name / address - ignored if {@code null}/empty
     * @param  entries The {@link HostConfigEntry}-ies to scan - ignored if {@code null}/empty
     * @return         A {@link List} of all the matching entries
     * @see            #isHostMatch(String, int)
     */
    public static List<HostConfigEntry> findMatchingEntries(String host, Collection<? extends HostConfigEntry> entries) {
        if (GenericUtils.isEmpty(host) || GenericUtils.isEmpty(entries)) {
            return Collections.emptyList();
        }

        List<HostConfigEntry> matches = null;
        for (HostConfigEntry entry : entries) {
            if (!entry.isHostMatch(host, 0 /* any port */)) {
                continue; // debug breakpoint
            }

            if (matches == null) {
                matches = new ArrayList<>(entries.size()); // in case ALL of them match
            }

            matches.add(entry);
        }

        if (matches == null) {
            return Collections.emptyList();
        } else {
            return matches;
        }
    }

    /**
     * @param  entries The entries - ignored if {@code null}/empty
     * @return         A {@link HostConfigEntryResolver} wrapper using the entries
     */
    public static HostConfigEntryResolver toHostConfigEntryResolver(Collection<? extends HostConfigEntry> entries) {
        if (GenericUtils.isEmpty(entries)) {
            return HostConfigEntryResolver.EMPTY;
        } else {
            return (host, port, lclAddress, username, proxyJump, ctx) -> {
                List<HostConfigEntry> matches = findMatchingEntries(host, entries);
                int numMatches = GenericUtils.size(matches);
                if (numMatches <= 0) {
                    return null;
                }

                // Collate attributes from all matching entries.
                HostConfigEntry entry = new HostConfigEntry(host, null, port, username);
                for (HostConfigEntry m : matches) {
                    entry.collate(m);
                }

                // Apply standard defaults.
                String temp = entry.getHostName();  // Remember that this was null above.
                if (temp == null || temp.isEmpty()) {
                    entry.setHostName(host);
                }
                temp = entry.getUsername();
                if (temp == null || temp.isEmpty()) {
                    entry.setUsername(OsUtils.getCurrentUser());
                }
                if (entry.getPort() < 1) {
                    entry.setPort(SshConstants.DEFAULT_PORT);
                }

                // Resolve file names
                Collection<String> identities = entry.getIdentities();
                if (!GenericUtils.isEmpty(identities)) {
                    identities = new ArrayList<>(identities);
                    entry.setIdentities(Collections.emptyList());
                    for (String id : identities) {
                        entry.addIdentity(
                                resolveIdentityFilePath(id, entry.getHostName(), entry.getPort(), entry.getUsername()));
                    }
                }
                // Same for CertificateFile
                String certificateFiles = entry.getProperty(CERTIFICATE_FILE_CONFIG_PROP);
                if (!GenericUtils.isEmpty(certificateFiles)) {
                    entry.removeProperty(CERTIFICATE_FILE_CONFIG_PROP);
                    String[] split = certificateFiles.split(",");
                    List<String> resolved = new ArrayList<>(split.length);
                    for (String raw : split) {
                        resolved.add(resolveIdentityFilePath(raw, entry.getHostName(), entry.getPort(), entry.getUsername()));
                    }
                    entry.processProperty(CERTIFICATE_FILE_CONFIG_PROP, resolved);
                }
                return entry;
            };
        }
    }

    public static List<HostConfigEntry> readHostConfigEntries(Path path, OpenOption... options) throws IOException {
        try (InputStream input = Files.newInputStream(path, options)) {
            return readHostConfigEntries(input, true);
        }
    }

    public static List<HostConfigEntry> readHostConfigEntries(URL url) throws IOException {
        try (InputStream input = url.openStream()) {
            return readHostConfigEntries(input, true);
        }
    }

    public static List<HostConfigEntry> readHostConfigEntries(InputStream inStream, boolean okToClose) throws IOException {
        try (Reader reader
                = new InputStreamReader(NoCloseInputStream.resolveInputStream(inStream, okToClose), StandardCharsets.UTF_8)) {
            return readHostConfigEntries(reader, true);
        }
    }

    public static List<HostConfigEntry> readHostConfigEntries(Reader rdr, boolean okToClose) throws IOException {
        try (BufferedReader buf = new BufferedReader(NoCloseReader.resolveReader(rdr, okToClose))) {
            return readHostConfigEntries(buf);
        }
    }

    /**
     * Reads configuration entries
     *
     * @param  rdr         The {@link BufferedReader} to use
     * @return             The {@link List} of read {@link HostConfigEntry}-ies
     * @throws IOException If failed to parse the read configuration
     */
    public static List<HostConfigEntry> readHostConfigEntries(BufferedReader rdr) throws IOException {
        HostConfigEntry curEntry = null;
        List<HostConfigEntry> entries = new ArrayList<>();

        int lineNumber = 1;
        for (String line = rdr.readLine(); line != null; line = rdr.readLine(), lineNumber++) {
            line = GenericUtils.replaceWhitespaceAndTrim(line);
            if (GenericUtils.isEmpty(line)) {
                continue;
            }

            // Strip off comments
            int pos = line.indexOf(ConfigFileReaderSupport.COMMENT_CHAR);
            if (pos == 0) {
                continue;
            }
            if (pos > 0) {
                line = line.substring(0, pos);
                line = line.trim();
            }

            /*
             * Some options use '=' as delimiter, others use ' '
             * TODO: This version treats '=' as taking precedence, but that means '=' can't show up
             * in a file name. A better approach is to break the line into tokens, possibly quoted,
             * then detect '='.
             */
            String key;
            String value;
            List<String> valsList;
            pos = line.indexOf('=');
            if (pos > 0) {
                key = line.substring(0, pos).trim();
                value = line.substring(pos + 1);
                valsList = new ArrayList<>(1);
                valsList.add(value);
            } else {
                pos = line.indexOf(' ');
                if (pos < 0) {
                    throw new StreamCorruptedException("No configuration value delimiter at line " + lineNumber + ": " + line);
                }
                key = line.substring(0, pos);
                value = line.substring(pos + 1);
                valsList = GenericUtils.filterToNotBlank(parseConfigValue(value));
            }

            // Detect transition to new entry.
            if (HOST_CONFIG_PROP.equalsIgnoreCase(key)) {
                if (GenericUtils.isEmpty(valsList)) {
                    throw new StreamCorruptedException("Missing host pattern(s) at line " + lineNumber + ": " + line);
                }

                if (curEntry != null) {
                    entries.add(curEntry);
                }
                curEntry = new HostConfigEntry();
                curEntry.setHost(valsList);
            } else if (MATCH_CONFIG_PROP.equalsIgnoreCase(key)) {
                throw new StreamCorruptedException("Currently not able to process Match sections");
            } else if (curEntry == null) {
                // Properties that occur before the first Host or Match keyword are a kind of global entry.
                curEntry = new HostConfigEntry();
                curEntry.setHost(Collections.singletonList(ALL_HOSTS_PATTERN));
            }

            String joinedValue = GenericUtils.join(valsList, ',');
            curEntry.appendPropertyValue(key, joinedValue);
            curEntry.processProperty(key, valsList);
        }

        if (curEntry != null) {
            entries.add(curEntry);
        }
        return entries;
    }

    public static void writeHostConfigEntries(
            Path path, Collection<? extends HostConfigEntry> entries, OpenOption... options)
            throws IOException {
        try (OutputStream outputStream = Files.newOutputStream(path, options)) {
            writeHostConfigEntries(outputStream, true, entries);
        }
    }

    public static void writeHostConfigEntries(
            OutputStream outputStream, boolean okToClose, Collection<? extends HostConfigEntry> entries)
            throws IOException {
        if (GenericUtils.isEmpty(entries)) {
            return;
        }

        try (Writer w = new OutputStreamWriter(
                NoCloseOutputStream.resolveOutputStream(outputStream, okToClose), StandardCharsets.UTF_8)) {
            appendHostConfigEntries(w, entries);
        }
    }

    public static <A extends Appendable> A appendHostConfigEntries(A sb, Collection<? extends HostConfigEntry> entries)
            throws IOException {
        if (GenericUtils.isEmpty(entries)) {
            return sb;
        }

        for (HostConfigEntry entry : entries) {
            entry.append(sb);
        }

        return sb;
    }

    /**
     * Checks if this is a multi-value - allow space and comma
     *
     * @todo         Handle quote marks.
     * @param  value The value - ignored if {@code null}/empty (after trimming)
     * @return       A {@link List} of the encountered values
     */
    public static List<String> parseConfigValue(String value) {
        String s = GenericUtils.replaceWhitespaceAndTrim(value);
        if (GenericUtils.isEmpty(s)) {
            return Collections.emptyList();
        }

        for (int index = 0; index < MULTI_VALUE_SEPARATORS.length(); index++) {
            char sep = MULTI_VALUE_SEPARATORS.charAt(index);
            int pos = s.indexOf(sep);
            if (pos >= 0) {
                String[] vals = GenericUtils.split(s, sep);
                if (GenericUtils.isEmpty(vals)) {
                    return Collections.emptyList();
                } else {
                    return Arrays.asList(vals);
                }
            }
        }

        // this point is reached if no separators found
        return Collections.singletonList(s);
    }

    // The file name may use the tilde syntax to refer to a user’s home directory or one of the following escape
    // characters:
    // '%d' (local user's home directory), '%u' (local user name), '%l' (local host name), '%h' (remote host name) or
    // '%r' (remote user name).
    public static String resolveIdentityFilePath(String id, String host, int port, String username) throws IOException {
        if (GenericUtils.isEmpty(id)) {
            return id;
        }

        String path = id.replace('/', File.separatorChar); // make sure all separators are local
        String[] elements = GenericUtils.split(path, File.separatorChar);
        StringBuilder sb = new StringBuilder(path.length() + Long.SIZE);
        for (int index = 0; index < elements.length; index++) {
            String elem = elements[index];
            if (index > 0) {
                sb.append(File.separatorChar);
            }

            for (int curPos = 0; curPos < elem.length(); curPos++) {
                char ch = elem.charAt(curPos);
                if (ch == PathUtils.HOME_TILDE_CHAR) {
                    ValidateUtils.checkTrue((curPos == 0) && (index == 0), "Home tilde must be first: %s", id);
                    PathUtils.appendUserHome(sb);
                } else if (ch == PATH_MACRO_CHAR) {
                    curPos++;
                    ValidateUtils.checkTrue(curPos < elem.length(), "Missing macro modifier in %s", id);
                    ch = elem.charAt(curPos);
                    switch (ch) {
                        case PATH_MACRO_CHAR:
                            sb.append(ch);
                            break;
                        case LOCAL_HOME_MACRO:
                            ValidateUtils.checkTrue((curPos == 1) && (index == 0), "Home macro must be first: %s", id);
                            PathUtils.appendUserHome(sb);
                            break;
                        case LOCAL_USER_MACRO:
                            sb.append(OsUtils.getCurrentUser());
                            break;
                        case LOCAL_HOST_MACRO: {
                            InetAddress address = Objects.requireNonNull(InetAddress.getLocalHost(), "No local address");
                            sb.append(ValidateUtils.checkNotNullAndNotEmpty(address.getHostName(), "No local name"));
                            break;
                        }
                        case REMOTE_HOST_MACRO:
                            sb.append(ValidateUtils.checkNotNullAndNotEmpty(host, "No remote host provided"));
                            break;
                        case REMOTE_USER_MACRO:
                            sb.append(ValidateUtils.hasContent(username, "No remote user provided"));
                            break;
                        case REMOTE_PORT_MACRO:
                            ValidateUtils.checkTrue(port > 0, "Bad remote port value: %d", port);
                            sb.append(port);
                            break;
                        default:
                            ValidateUtils.throwIllegalArgumentException("Bad modifier '%s' in %s", String.valueOf(ch), id);
                    }
                } else {
                    sb.append(ch);
                }
            }
        }

        return sb.toString();
    }

    /**
     * @return The default {@link Path} location of the OpenSSH hosts entries configuration file
     */
    @SuppressWarnings("synthetic-access")
    public static Path getDefaultHostConfigFile() {
        return LazyDefaultConfigFileHolder.CONFIG_FILE;
    }
}
