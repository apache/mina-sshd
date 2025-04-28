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
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.auth.MutableUserHolder;
import org.apache.sshd.common.config.ConfigFileReaderSupport;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils;
import org.apache.sshd.common.util.MapEntryUtils.NavigableMapBuilder;
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
    public static final String CERTIFICATE_FILE_CONFIG_PROP = "CertificateFile";
    public static final String LOCAL_FORWARD_CONFIG_PROP = "LocalForward";
    public static final String REMOTE_FORWARD_CONFIG_PROP = "RemoteForward";
    public static final String SEND_ENV_CONFIG_PROP = "SendEnv";
    public static final String SET_ENV_CONFIG_PROP = "SetEnv";
    public static final String PUBKEY_ACCEPTED_ALGORITHMS_CONFIG_PROP = "PubkeyAcceptedAlgorithms";
    public static final String ADD_KEYS_TO_AGENT_CONFIG_PROP = "AddKeysToAgent";
    public static final String CANONICAL_DOMAINS_CONFIG_PROP = "CanonicalDomains";
    public static final String GLOBAL_KNOWN_HOSTS_CONFIG_PROP = "GlobalKnownHostsFile";
    public static final String USER_KNOWN_HOSTS_CONFIG_PROP = "UserKnownHostsFile";

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

    public static final String MULTI_VALUE_SEPARATORS = " ,";

    public static final char PATH_MACRO_CHAR = '%';
    public static final char LOCAL_HOME_MACRO = 'd';
    public static final char LOCAL_USER_MACRO = 'u';
    public static final char LOCAL_HOST_MACRO = 'l';
    public static final char REMOTE_HOST_MACRO = 'h';
    public static final char REMOTE_USER_MACRO = 'r';
    // Extra - not part of the standard
    public static final char REMOTE_PORT_MACRO = 'p';

    /**
     * Unmodifiable set of OpenSSH config file keys that can be specified multiple times building up a list. All other
     * keys follow a "first match wins" rule.
     */
    public static final Set<String> ADDITIVE_KEYS = Collections
            .unmodifiableSet(GenericUtils.asSortedSet(String.CASE_INSENSITIVE_ORDER, //
                    CERTIFICATE_FILE_CONFIG_PROP, //
                    IDENTITY_FILE_CONFIG_PROP, //
                    LOCAL_FORWARD_CONFIG_PROP, //
                    REMOTE_FORWARD_CONFIG_PROP, //
                    SEND_ENV_CONFIG_PROP, //
                    SET_ENV_CONFIG_PROP));

    /**
     * Unmodifiable set of OpenSSH config file keys that take a whitespace-separated list of values.
     */
    public static final Set<String> LIST_KEYS = Collections
            .unmodifiableSet(GenericUtils.asSortedSet(String.CASE_INSENSITIVE_ORDER, //
                    ADD_KEYS_TO_AGENT_CONFIG_PROP, //
                    CANONICAL_DOMAINS_CONFIG_PROP, //
                    GLOBAL_KNOWN_HOSTS_CONFIG_PROP, //
                    SEND_ENV_CONFIG_PROP, //
                    SET_ENV_CONFIG_PROP, //
                    USER_KNOWN_HOSTS_CONFIG_PROP));

    /**
     * A modifiable map of config key aliases, mapping aliases to a canonical name. Keys are aliases, values are the
     * canonical names.
     */
    public static final Map<String, String> KEY_ALIASES = NavigableMapBuilder
            .<String, String> builder(String.CASE_INSENSITIVE_ORDER)
            .put("PubkeyAcceptedKeyTypes", PUBKEY_ACCEPTED_ALGORITHMS_CONFIG_PROP) //
            .concurrent();

    private static final class LazyDefaultConfigFileHolder {
        private static final Path CONFIG_FILE = PublicKeyEntry.getDefaultKeysFolderPath().resolve(STD_CONFIG_FILENAME);

        private LazyDefaultConfigFileHolder() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }

    protected String hostPatterns;

    protected final Map<String, List<String>> properties = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

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
        if (that == null) {
            return;
        }
        that.properties.forEach((k, l) -> {
            if (ADDITIVE_KEYS.contains(k)) {
                properties.computeIfAbsent(k, x -> new ArrayList<>()).addAll(l);
            } else if (!properties.containsKey(k)) {
                properties.put(k, new ArrayList<>(l));
            }
        });
    }

    /**
     * @return The <U>pattern(s)</U> represented by this entry
     */
    public String getHost() {
        return hostPatterns;
    }

    public void setHost(String host) {
        this.hostPatterns = host;
        setPatterns(parsePatterns(parseConfigValue(host)));
    }

    public void setHost(Collection<String> patterns) {
        this.hostPatterns = GenericUtils.join(ValidateUtils.checkNotNullAndNotEmpty(patterns, "No patterns"), ',');
        setPatterns(parsePatterns(patterns));
    }

    /**
     * @return The effective host name to connect to if the pattern matches
     */
    public String getHostName() {
        return getProperty(HOST_NAME_CONFIG_PROP);
    }

    public void setHostName(String hostName) {
        setProperty(HOST_NAME_CONFIG_PROP, hostName);
    }

    /**
     * @return A port override - if positive
     */
    public int getPort() {
        String value = getProperty(PORT_CONFIG_PROP);
        if (value == null) {
            return -1;
        }
        return Integer.valueOf(value);
    }

    public void setPort(int port) {
        if (port <= 0) {
            properties.remove(PORT_CONFIG_PROP);
        } else {
            setProperty(PORT_CONFIG_PROP, Integer.toString(port));
        }
    }

    /**
     * @return A username override - if not {@code null}/empty
     */
    @Override
    public String getUsername() {
        return getProperty(USER_CONFIG_PROP);
    }

    @Override
    public void setUsername(String username) {
        setProperty(USER_CONFIG_PROP, username);
    }

    /**
     * @return the host to use as a proxy
     */
    public String getProxyJump() {
        return getProperty(PROXY_JUMP_CONFIG_PROP);
    }

    public void setProxyJump(String proxyJump) {
        setProperty(PROXY_JUMP_CONFIG_PROP, proxyJump);
    }

    /**
     * @return The current identities file paths; may be empty
     */
    public Collection<String> getIdentities() {
        List<String> identities = properties.get(IDENTITY_FILE_CONFIG_PROP);
        return identities == null ? Collections.emptyList() : identities;
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
        ValidateUtils.hasContent(id, "No identity provided");
        setProperty(IDENTITY_FILE_CONFIG_PROP, id);
    }

    public void setIdentities(Collection<String> identities) {
        properties.remove(IDENTITY_FILE_CONFIG_PROP);
        if (identities != null) {
            identities.forEach(this::addIdentity);
        }
    }

    /**
     * @return {@code true} if must use only the identities in this entry
     */
    public boolean isIdentitiesOnly() {
        return ConfigFileReaderSupport.parseBooleanValue(getProperty(EXCLUSIVE_IDENTITIES_CONFIG_PROP));
    }

    public void setIdentitiesOnly(boolean identitiesOnly) {
        setProperty(EXCLUSIVE_IDENTITIES_CONFIG_PROP, ConfigFileReaderSupport.yesNoValueOf(identitiesOnly));
    }

    /**
     * Retrieves the raw {@link Map} of properties.
     */
    public Map<String, List<String>> getProperties() {
        return properties;
    }

    public void clear() {
        properties.clear();
        hostPatterns = null;
        setPatterns(new LinkedList<>());
    }

    /**
     * Retrieves all the values of a property. If the property an {@link #ADDITIVE_KEYS additive} or {@link #LIST_KEYS
     * list-valued} property, the result may contain more than one value.
     *
     * @param  name of the property to get the values of; must not be {@code null} or empty
     * @return      the values, as an unmodifiable list, may be {@code null}
     */
    public List<String> getValues(String name) {
        String key = ValidateUtils.checkNotNullAndNotEmpty(name, "No property name");
        String alias = KEY_ALIASES.get(key);
        if (alias != null) {
            key = alias;
        }
        List<String> values = properties.get(key);
        return values == null ? null : Collections.unmodifiableList(values);
    }

    /**
     * Retrieves the single value of a property. If called for an {@link #ADDITIVE_KEYS additive} or {@link #LIST_KEYS
     * list-valued} key that has several values, only the first one is returned.
     *
     * @param  name of the property to get the values of; must not be {@code null} or empty
     * @return      the property value or {@code null} if not set
     * @see         #getProperty(String, String)
     */
    public String getProperty(String name) {
        return getProperty(name, null);
    }

    /**
     * Retrieves the single value of a property. If called for an {@link #ADDITIVE_KEYS additive} or {@link #LIST_KEYS
     * list-valued} key that has several values, only the first one is returned. If the property is not set, returns the
     * given {@code defaultValue}.
     *
     * @param  name         of the property to get the values of; must not be {@code null} or empty
     * @param  defaultValue value to return if not set, may be {@code null}
     * @return              the property value or {@code defaultValue} if not set
     */
    public String getProperty(String name, String defaultValue) {
        List<String> values = getValues(name);
        if (values == null || values.isEmpty()) {
            return defaultValue;
        }
        return values.get(0);
    }

    /**
     * Sets or replaces the property value. If the {@code value} is {@code null} or empty, the property is removed.
     * Otherwise, if it's a {@link #ADDITIVE_KEYS additive} property, the new value is added to any previously added
     * values. Otherwise, the existing value is replaced by the new value.
     *
     * @param name  of the property to set the value; must not be {@code null} or empty
     * @param value to set; if {@code null} or empty, the property is removed
     */
    public void setProperty(String name, String value) {
        if (GenericUtils.isEmpty(value)) {
            removeProperty(name);
        } else {
            String key = toKey(name);
            List<String> values = properties.computeIfAbsent(key, k -> new ArrayList<>());
            if (!ADDITIVE_KEYS.contains(key)) {
                values.clear();
            }
            values.add(value);
        }
    }

    /**
     * Sets or replaces the property value. If the {@code value} is {@code null} or empty, the property is removed.
     * Otherwise, the existing value is replaced by the new value.
     *
     * @param name  of the property to set the value; must not be {@code null} or empty
     * @param value to set; if {@code null} or empty, the property is removed
     */
    public void setProperty(String name, List<String> value) {
        if (GenericUtils.isEmpty(value)) {
            removeProperty(name);
        } else {
            String key = toKey(name);
            List<String> values = properties.computeIfAbsent(key, k -> new ArrayList<>());
            values.clear();
            values.addAll(value);
        }
    }

    /**
     * Removes a property.
     *
     * @param  name Property name - never {@code null}/empty
     * @return      The removed property value - {@code null} if no such property name
     */
    public List<String> removeProperty(String name) {
        return properties.remove(toKey(name));
    }

    /**
     * Writes a string representation with each property on a line to the given {@link Appendable}, using
     * {@link System#lineSeparator()} to end each line.
     *
     * @param  <A>         The {@link Appendable} type
     * @param  sb          The {@link Appendable} to write to
     * @return             {@code sb}
     * @throws IOException
     */
    public <A extends Appendable> A append(A sb) throws IOException {
        sb.append(HOST_CONFIG_PROP).append(' ') //
                .append(ValidateUtils.checkNotNullAndNotEmpty(getHost(), "No host pattern"))
                .append(IoUtils.EOL);
        appendNonEmptyProperties(sb, getProperties());
        return sb;
    }

    @Override
    public String toString() {
        return getHost() + ": " + getUsername() + "@" + getHostName() + ":" + getPort();
    }

    private static String toKey(String name) {
        String key = ValidateUtils.checkNotNullAndNotEmpty(name, "No property name");
        String alias = KEY_ALIASES.get(key);
        return alias != null ? alias : key;
    }

    /**
     * Appends the properties.
     *
     * @param  <A>         The {@link Appendable} type
     * @param  sb          The target appender
     * @param  props       The {@link Map} of properties - ignored if {@code null}/empty
     * @return             the target appender
     * @throws IOException
     * @see                #appendNonEmptyProperty(Appendable, String, Object)
     */
    public static <A extends Appendable> A appendNonEmptyProperties(A sb, Map<String, List<String>> props) throws IOException {
        if (MapEntryUtils.isEmpty(props)) {
            return sb;
        }

        appendNonEmptyProperty(sb, HOST_NAME_CONFIG_PROP, props.get(HOST_NAME_CONFIG_PROP));
        appendNonEmptyProperty(sb, PORT_CONFIG_PROP, props.get(PORT_CONFIG_PROP));
        appendNonEmptyProperty(sb, USER_CONFIG_PROP, props.get(USER_CONFIG_PROP));

        for (Map.Entry<String, List<String>> entry : props.entrySet()) {
            String key = entry.getKey();
            if (HOST_NAME_CONFIG_PROP.equalsIgnoreCase(key) //
                    || PORT_CONFIG_PROP.equalsIgnoreCase(key) //
                    || USER_CONFIG_PROP.equalsIgnoreCase(key)) {
                continue;
            }
            appendNonEmptyProperty(sb, key, entry.getValue());
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
     * @throws IOException
     * @see                #appendNonEmptyValues(Appendable, String, Object...)
     */
    public static <A extends Appendable> A appendNonEmptyProperty(A sb, String name, List<String> value) throws IOException {
        String key = ValidateUtils.checkNotNullAndNotEmpty(name, "No property name");
        String alias = KEY_ALIASES.get(key);
        if (alias != null) {
            key = alias;
        }
        if (ADDITIVE_KEYS.contains(key)) {
            // Write multiple lines
            for (String s : value) {
                if (!GenericUtils.isEmpty(s)) {
                    sb.append("    ").append(key).append(' ');
                    if (LOCAL_FORWARD_CONFIG_PROP.equalsIgnoreCase(key) || REMOTE_FORWARD_CONFIG_PROP.equalsIgnoreCase(key)) {
                        String[] parts = s.split(" ", 2);
                        appendValue(sb, parts[0]);
                        if (parts.length > 1) {
                            sb.append(' ');
                            appendValue(sb, parts[1]);
                        }
                    } else {
                        appendValue(sb, s);
                    }
                    sb.append(IoUtils.EOL);
                }
            }
        } else {
            sb.append("    ").append(key).append(' ');
            for (String s : value) {
                if (!GenericUtils.isEmpty(s)) {
                    appendValue(sb, s);
                }
            }
            sb.append(IoUtils.EOL);
        }
        return sb;
    }

    public static <A extends Appendable> A appendValue(A sb, String value) throws IOException {
        if (value.indexOf(' ') < 0 && value.indexOf('\\') < 0) {
            sb.append(value);
            return sb;
        }
        sb.append('"');
        int i = 0;
        int end = value.length();
        while (i < end) {
            char ch = value.charAt(i++);
            if (ch == '"' || ch == '\\') {
                sb.append('\\').append(ch);
            } else {
                sb.append(ch);
            }
        }
        sb.append('"');
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
                List<String> certificateFiles = entry.getValues(CERTIFICATE_FILE_CONFIG_PROP);
                if (!GenericUtils.isEmpty(certificateFiles)) {
                    entry.removeProperty(CERTIFICATE_FILE_CONFIG_PROP);
                    for (String raw : certificateFiles) {
                        entry.setProperty(CERTIFICATE_FILE_CONFIG_PROP,
                                resolveIdentityFilePath(raw, entry.getHostName(), entry.getPort(), entry.getUsername()));
                    }
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
            if (GenericUtils.isEmpty(line) || line.charAt(0) == ConfigFileReaderSupport.COMMENT_CHAR) {
                continue;
            }
            String[] parts = line.split(" *[= ]", 2);
            String keyword = parts[0].trim();
            if (keyword.isEmpty()) {
                continue;
            }
            int i = keyword.indexOf(ConfigFileReaderSupport.COMMENT_CHAR);
            if (i >= 0) {
                keyword = keyword.substring(0, i);
            }
            if (keyword.isEmpty()) {
                continue;
            }
            List<String> values = null;
            String rest = (i < 0 && parts.length > 1) ? parts[1].trim() : "";
            if (!rest.isEmpty()) {
                values = parseList(rest);
            }
            // Detect transition to new entry.
            if (HOST_CONFIG_PROP.equalsIgnoreCase(keyword)) {
                if (GenericUtils.isEmpty(values)) {
                    throw new StreamCorruptedException("Missing host pattern(s) at line " + lineNumber + ": " + line);
                }

                if (curEntry != null) {
                    entries.add(curEntry);
                }
                curEntry = new HostConfigEntry();
                curEntry.setHost(values);
                continue;
            } else if (MATCH_CONFIG_PROP.equalsIgnoreCase(keyword)) {
                throw new StreamCorruptedException("Currently not able to process Match sections");
            } else if (curEntry == null) {
                // Properties that occur before the first Host or Match keyword are a kind of global entry.
                curEntry = new HostConfigEntry();
                curEntry.setHost(Collections.singletonList(ALL_HOSTS_PATTERN));
            }
            if (values != null && !values.isEmpty()) {
                if (LIST_KEYS.contains(keyword)) {
                    if (ADDITIVE_KEYS.contains(keyword)) {
                        for (String value : values) {
                            curEntry.setProperty(keyword, value);
                        }
                    } else {
                        curEntry.setProperty(keyword, values);
                    }
                } else if (LOCAL_FORWARD_CONFIG_PROP.equalsIgnoreCase(keyword)
                        || REMOTE_FORWARD_CONFIG_PROP.equalsIgnoreCase(keyword)) {
                    String value = values.get(0);
                    if (values.size() > 1) {
                        value += ' ' + values.get(1);
                    }
                    curEntry.setProperty(keyword, value);
                } else {
                    curEntry.setProperty(keyword, values.get(0));
                }
            }
        }

        if (curEntry != null) {
            entries.add(curEntry);
        }
        return entries;
    }

    /**
     * Splits the argument into a list of whitespace-separated elements. Elements containing whitespace must be quoted
     * and will be de-quoted. Backslash-escapes are handled for quotes and blanks.
     *
     * @param  argument argument part of the configuration line as read from the config file
     * @return          a {@link List} of elements, possibly empty and possibly containing empty elements, but not
     *                  containing {@code null}
     */
    public static List<String> parseList(String argument) {
        List<String> result = new ArrayList<>();
        int start = 0;
        int length = argument.length();
        while (start < length) {
            // Skip whitespace
            char ch = argument.charAt(start);
            if (Character.isWhitespace(ch)) {
                start++;
            } else if (ch == '#') {
                break; // Comment start
            } else {
                // Parse one token now.
                start = parseToken(argument, start, length, result);
            }
        }
        return result;
    }

    /**
     * Parses a token up to the next whitespace not inside a string quoted by single or double quotes. Inside a string,
     * quotes can be escaped by backslash characters. Outside of a string, "\ " can be used to include a space in a
     * token; inside a string "\ " is taken literally as '\' followed by ' '.
     *
     * @param  argument to parse the token out of
     * @param  from     index at the beginning of the token
     * @param  to       index one after the last character to look at
     * @param  result   a list collecting tokens to which the parsed token is added
     * @return          the index after the token
     */
    public static int parseToken(String argument, int from, int to, List<String> result) {
        if (from >= to) {
            return from;
        }
        // Not quoted: consume up to the next un-escaped space or comment character. OpenSSH recognizes the backslash as
        // an escape character for backslashes and single or double quotes. A quoted part is delimited by non-escaped
        // single or double quotes. Outside of a quoted part, the backslash also escapes a blank.
        StringBuilder b = new StringBuilder();
        int i = from;
        boolean escaped = false; // true if the last character was a backslash.
        char quote = 0;
        while (i < to) {
            char ch = argument.charAt(i++);
            if (ch == '\'' || ch == '"') {
                if (escaped) {
                    b.append(ch);
                    escaped = false;
                } else if (quote == ch) {
                    quote = 0;
                } else if (quote == 0) {
                    quote = ch;
                } else {
                    b.append(ch);
                }
            } else if (ch == '#') {
                if (quote == 0) {
                    break;
                }
                b.append(ch);
            } else if (ch == ' ') {
                if (quote == 0 && !escaped) {
                    break;
                } else if (quote != 0 && escaped) {
                    b.append('\\');
                }
                b.append(ch);
                escaped = false;
            } else if (ch == '\\') {
                if (escaped) {
                    b.append(ch);
                }
                escaped = !escaped;
            } else {
                if (escaped) {
                    b.append('\\');
                    escaped = false;
                }
                b.append(ch);
            }
        }
        if (escaped) {
            b.append('\\');
        }
        if (b.length() > 0) {
            result.add(b.toString());
        }
        return i;
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

    /**
     * Writes all given entries to the given {@link Appendable}.
     *
     * @param  <A>         The {@link Appendable} type
     * @param  sb          The {@link Appendable} to write to
     * @param  entries     the entries to write
     * @return             {@code sb}
     * @throws IOException
     */
    public static <A extends Appendable> A appendHostConfigEntries(A sb, Collection<? extends HostConfigEntry> entries)
            throws IOException {
        if (!GenericUtils.isEmpty(entries)) {
            for (HostConfigEntry entry : entries) {
                entry.append(sb);
            }
        }
        return sb;
    }

    /**
     * Parses a host config value in a list of whitespace-separated elements, handling OpenSSH-style quoting.
     *
     * @param  value The value - ignored if {@code null}/empty (after trimming)
     * @return       A {@link List} of the encountered values
     */
    public static List<String> parseConfigValue(String value) {
        return parseList(GenericUtils.replaceWhitespaceAndTrim(value));
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
