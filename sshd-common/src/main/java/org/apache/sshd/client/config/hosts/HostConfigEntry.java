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
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.TreeMap;

import org.apache.sshd.common.auth.MutableUserHolder;
import org.apache.sshd.common.config.ConfigFileReaderSupport;
import org.apache.sshd.common.config.keys.IdentityUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils.NavigableMapBuilder;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.NoCloseInputStream;
import org.apache.sshd.common.util.io.NoCloseOutputStream;
import org.apache.sshd.common.util.io.NoCloseReader;

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
    public static final String HOST_NAME_CONFIG_PROP = "HostName";
    public static final String PORT_CONFIG_PROP = ConfigFileReaderSupport.PORT_CONFIG_PROP;
    public static final String USER_CONFIG_PROP = "User";
    public static final String PROXY_JUMP_CONFIG_PROP = "ProxyJump";
    public static final String IDENTITY_FILE_CONFIG_PROP = "IdentityFile";
    /**
     * Use only the identities specified in the host entry (if any)
     */
    public static final String EXCLUSIVE_IDENTITIES_CONFIG_PROP = "IdentitiesOnly";
    public static final boolean DEFAULT_EXCLUSIVE_IDENTITIES = false;

    /**
     * A case <U>insensitive</U> {@link NavigableSet} of the properties that receive special handling
     */
    public static final NavigableSet<String> EXPLICIT_PROPERTIES = Collections.unmodifiableNavigableSet(
            GenericUtils.asSortedSet(String.CASE_INSENSITIVE_ORDER,
                    HOST_CONFIG_PROP, HOST_NAME_CONFIG_PROP, PORT_CONFIG_PROP,
                    USER_CONFIG_PROP, IDENTITY_FILE_CONFIG_PROP, EXCLUSIVE_IDENTITIES_CONFIG_PROP));

    public static final String MULTI_VALUE_SEPARATORS = " ,";

    public static final char HOME_TILDE_CHAR = '~';
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

    private String host;
    private String hostName;
    private int port;
    private String username;
    private String proxyJump;
    private Boolean exclusiveIdentites;
    private Collection<String> identities = Collections.emptyList();
    private Map<String, String> properties = Collections.emptyMap();

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
    }

    public String resolveHostName(String originalHost) {
        return resolveHostName(originalHost, getHostName());
    }

    /**
     * @return A port override - if positive
     */
    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    /**
     * Resolves the effective port to use
     *
     * @param  originalPort The original requested port
     * @return              If the host entry port is positive, then it is used, otherwise the original requested port
     * @see                 #resolvePort(int, int)
     */
    public int resolvePort(int originalPort) {
        return resolvePort(originalPort, getPort());
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
    }

    /**
     * Resolves the effective username
     *
     * @param  originalUser The original requested username
     * @return              If the configured host entry username is not {@code null}/empty then it is used, otherwise
     *                      the original one.
     * @see                 #resolveUsername(String)
     */
    public String resolveUsername(String originalUser) {
        return resolveUsername(originalUser, getUsername());
    }

    /**
     * @return the host to use as a proxy
     */
    public String getProxyJump() {
        return proxyJump;
    }

    public void setProxyJump(String proxyJump) {
        this.proxyJump = proxyJump;
    }

    /**
     * Resolves the effective proxyJump
     *
     * @param  originalProxyJump The original requested proxyJump
     * @return                   If the configured host entry proxyJump is not {@code null}/empty then it is used,
     *                           otherwise the original one.
     * @see                      #resolveUsername(String)
     */
    public String resolveProxyJump(String originalProxyJump) {
        return resolveProxyJump(originalProxyJump, getProxyJump());
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
        String path = ValidateUtils.checkNotNullAndNotEmpty(id, "No identity provided");
        if (GenericUtils.isEmpty(identities)) {
            identities = new LinkedList<>();
        }
        identities.add(path);
    }

    public void setIdentities(Collection<String> identities) {
        this.identities = (identities == null) ? Collections.emptyList() : identities;
    }

    /**
     * @return {@code true} if must use only the identities in this entry
     */
    public boolean isIdentitiesOnly() {
        return (exclusiveIdentites == null) ? DEFAULT_EXCLUSIVE_IDENTITIES : exclusiveIdentites;
    }

    public void setIdentitiesOnly(boolean identitiesOnly) {
        exclusiveIdentites = identitiesOnly;
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
        if (GenericUtils.isEmpty(props)) {
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
     * Updates the values that are <U>not</U> already configured with those from the global entry
     *
     * @param  globalEntry The global entry - ignored if {@code null} or same reference as this entry
     * @return             {@code true} if anything updated
     */
    public boolean processGlobalValues(HostConfigEntry globalEntry) {
        if ((globalEntry == null) || (this == globalEntry)) {
            return false;
        }

        boolean modified = false;
        /*
         * NOTE !!! DO NOT TRY TO CHANGE THE ORDER OF THE OR-ing AS IT WOULD CAUSE INVALID CODE EXECUTION
         */
        modified = updateGlobalPort(globalEntry.getPort()) || modified;
        modified = updateGlobalHostName(globalEntry.getHostName()) || modified;
        modified = updateGlobalUserName(globalEntry.getUsername()) || modified;
        modified = updateGlobalIdentities(globalEntry.getIdentities()) || modified;
        modified = updateGlobalIdentityOnly(globalEntry.isIdentitiesOnly()) || modified;

        Map<String, String> updated = updateGlobalProperties(globalEntry.getProperties());
        modified = (GenericUtils.size(updated) > 0) || modified;

        return modified;
    }

    /**
     * Sets all the properties for which no current value exists in the entry
     *
     * @param  props The global properties - ignored if {@code null}/empty
     * @return       A {@link Map} of the <U>updated</U> properties
     */
    public Map<String, String> updateGlobalProperties(Map<String, String> props) {
        if (GenericUtils.isEmpty(props)) {
            return Collections.emptyMap();
        }

        Map<String, String> updated = null;
        // Cannot use forEach because of the modification of the updated map value (non-final)
        for (Map.Entry<String, String> pe : props.entrySet()) {
            String key = pe.getKey();
            String curValue = getProperty(key);
            if (GenericUtils.length(curValue) > 0) {
                continue;
            }

            String newValue = pe.getValue();
            setProperty(key, newValue);

            if (updated == null) {
                updated = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            }

            updated.put(key, newValue);
        }

        if (updated == null) {
            return Collections.emptyMap();
        } else {
            return updated;
        }
    }

    /**
     * @param  ids Global identities - ignored if {@code null}/empty or already have configured identities
     * @return     {@code true} if updated identities
     */
    public boolean updateGlobalIdentities(Collection<String> ids) {
        if (GenericUtils.isEmpty(ids) || (GenericUtils.size(getIdentities()) > 0)) {
            return false;
        }

        for (String id : ids) {
            addIdentity(id);
        }

        return true;
    }

    /**
     * @param  user The global user name - ignored if {@code null}/empty or already have a configured user
     * @return      {@code true} if updated the username
     */
    public boolean updateGlobalUserName(String user) {
        if (GenericUtils.isEmpty(user) || (GenericUtils.length(getUsername()) > 0)) {
            return false;
        }

        setUsername(user);
        return true;
    }

    /**
     * @param  name The global host name - ignored if {@code null}/empty or already have a configured target host
     * @return      {@code true} if updated the target host
     */
    public boolean updateGlobalHostName(String name) {
        if (GenericUtils.isEmpty(name) || (GenericUtils.length(getHostName()) > 0)) {
            return false;
        }

        setHostName(name);
        return true;
    }

    /**
     * @param  portValue The global port value - ignored if not positive or already have a configured port
     * @return           {@code true} if updated the port value
     */
    public boolean updateGlobalPort(int portValue) {
        if ((portValue <= 0) || (getPort() > 0)) {
            return false;
        }

        setPort(portValue);
        return true;
    }

    /**
     * @param  identitiesOnly Whether to use only the identities in this entry. Ignored if already set
     * @return                {@code true} if updated the option value
     */
    public boolean updateGlobalIdentityOnly(boolean identitiesOnly) {
        if (exclusiveIdentites != null) {
            return false;
        }

        setIdentitiesOnly(identitiesOnly);
        return true;
    }

    /**
     * @param  name                     Property name - never {@code null}/empty
     * @param  valsList                 The available values for the property
     * @param  ignoreAlreadyInitialized If {@code false} and one of the &quot;known&quot; properties is encountered then
     *                                  throws an exception
     * @throws IllegalArgumentException If an existing value is overwritten and <tt>ignoreAlreadyInitialized</tt> is
     *                                  {@code false} (except for {@link #IDENTITY_FILE_CONFIG_PROP} which is
     *                                  <U>cumulative</U>
     * @see                             #HOST_NAME_CONFIG_PROP
     * @see                             #PORT_CONFIG_PROP
     * @see                             #USER_CONFIG_PROP
     * @see                             #IDENTITY_FILE_CONFIG_PROP
     */
    public void processProperty(String name, Collection<String> valsList, boolean ignoreAlreadyInitialized) {
        String key = ValidateUtils.checkNotNullAndNotEmpty(name, "No property name");
        String joinedValue = GenericUtils.join(valsList, ',');
        appendPropertyValue(key, joinedValue);

        if (HOST_NAME_CONFIG_PROP.equalsIgnoreCase(key)) {
            ValidateUtils.checkTrue(GenericUtils.size(valsList) == 1, "Multiple target hosts N/A: %s", joinedValue);

            String curValue = getHostName();
            ValidateUtils.checkTrue(GenericUtils.isEmpty(curValue) || ignoreAlreadyInitialized, "Already initialized %s: %s",
                    key, curValue);
            setHostName(joinedValue);
        } else if (PORT_CONFIG_PROP.equalsIgnoreCase(key)) {
            ValidateUtils.checkTrue(GenericUtils.size(valsList) == 1, "Multiple target ports N/A: %s", joinedValue);

            int curValue = getPort();
            ValidateUtils.checkTrue((curValue <= 0) || ignoreAlreadyInitialized, "Already initialized %s: %d", key, curValue);

            int newValue = Integer.parseInt(joinedValue);
            ValidateUtils.checkTrue(newValue > 0, "Bad new port value: %d", newValue);
            setPort(newValue);
        } else if (USER_CONFIG_PROP.equalsIgnoreCase(key)) {
            ValidateUtils.checkTrue(GenericUtils.size(valsList) == 1, "Multiple target users N/A: %s", joinedValue);

            String curValue = getUsername();
            ValidateUtils.checkTrue(GenericUtils.isEmpty(curValue) || ignoreAlreadyInitialized, "Already initialized %s: %s",
                    key, curValue);
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
            String curValue = getProxyJump();
            ValidateUtils.checkTrue(GenericUtils.isEmpty(curValue) || ignoreAlreadyInitialized, "Already initialized %s: %s",
                    key, curValue);
            setProxyJump(joinedValue);
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
        if (GenericUtils.isEmpty(properties)) {
            properties = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        }

        return properties.put(key, value);
    }

    /**
     * @param  name Property name - never {@code null}/empty
     * @return      The removed property value - {@code null} if no such property name
     */
    public String removeProperty(String name) {
        String key = ValidateUtils.checkNotNullAndNotEmpty(name, "No property name");
        Map<String, String> props = getProperties();
        if (GenericUtils.isEmpty(props)) {
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
        this.properties = (properties == null) ? Collections.emptyMap() : properties;
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
        if (GenericUtils.isEmpty(props)) {
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
     * @param  entries The entries - ignored if {@code null}/empty
     * @return         A {@link HostConfigEntryResolver} wrapper using the entries
     */
    public static HostConfigEntryResolver toHostConfigEntryResolver(Collection<? extends HostConfigEntry> entries) {
        if (GenericUtils.isEmpty(entries)) {
            return HostConfigEntryResolver.EMPTY;
        } else {
            return (host1, port1, lclAddress, username1, proxyJump1, ctx) -> {
                List<HostConfigEntry> matches = findMatchingEntries(host1, entries);
                int numMatches = GenericUtils.size(matches);
                if (numMatches <= 0) {
                    return null;
                }

                HostConfigEntry match = (numMatches == 1) ? matches.get(0) : findBestMatch(matches);
                if (match == null) {
                    ValidateUtils.throwIllegalArgumentException("No best match found for %s@%s:%d out of %d matches", username1,
                            host1, port1, numMatches);
                }

                return normalizeEntry(match, host1, port1, username1, proxyJump1);
            };
        }
    }

    /**
     * @param  entry       The original entry - ignored if {@code null}
     * @param  host        The original host name / address
     * @param  port        The original port
     * @param  username    The original user name
     * @param  proxyJump   And optional proxy jump setting
     * @return             A <U>cloned</U> entry whose values are resolved - including expanding macros in the
     *                     identities files
     * @throws IOException If failed to normalize the entry
     * @see                #resolveHostName(String)
     * @see                #resolvePort(int)
     * @see                #resolveUsername(String)
     * @see                #resolveIdentityFilePath(String, String, int, String)
     */
    public static HostConfigEntry normalizeEntry(
            HostConfigEntry entry, String host, int port, String username, String proxyJump)
            throws IOException {
        if (entry == null) {
            return null;
        }

        HostConfigEntry normal = new HostConfigEntry();
        normal.setHost(host);
        normal.setHostName(entry.resolveHostName(host));
        normal.setPort(entry.resolvePort(port));
        normal.setUsername(entry.resolveUsername(username));
        normal.setProxyJump(entry.resolveProxyJump(proxyJump));

        Map<String, String> props = entry.getProperties();
        if (GenericUtils.size(props) > 0) {
            normal.setProperties(
                    NavigableMapBuilder.<String, String> builder(String.CASE_INSENSITIVE_ORDER)
                            .putAll(props)
                            .build());
        }

        Collection<String> ids = entry.getIdentities();
        if (GenericUtils.isEmpty(ids)) {
            return normal;
        }

        normal.setIdentities(Collections.emptyList()); // start fresh
        for (String id : ids) {
            String path = resolveIdentityFilePath(id, host, port, username);
            normal.addIdentity(path);
        }

        return normal;
    }

    /**
     * Resolves the effective target host
     *
     * @param  originalName The original requested host
     * @param  entryName    The configured host
     * @return              If the configured host entry is not {@code null}/empty then it is used, otherwise the
     *                      original one.
     */
    public static String resolveHostName(String originalName, String entryName) {
        if (GenericUtils.isEmpty(entryName)) {
            return originalName;
        } else {
            return entryName;
        }
    }

    /**
     * Resolves the effective username
     *
     * @param  originalUser The original requested username
     * @param  entryUser    The configured host entry username
     * @return              If the configured host entry username is not {@code null}/empty then it is used, otherwise
     *                      the original one.
     */
    public static String resolveUsername(String originalUser, String entryUser) {
        if (GenericUtils.isEmpty(entryUser)) {
            return originalUser;
        } else {
            return entryUser;
        }
    }

    /**
     * Resolves the effective port to use
     *
     * @param  originalPort The original requested port
     * @param  entryPort    The configured host entry port
     * @return              If the host entry port is positive, then it is used, otherwise the original requested port
     */
    public static int resolvePort(int originalPort, int entryPort) {
        if (entryPort <= 0) {
            return originalPort;
        } else {
            return entryPort;
        }
    }

    /**
     * Resolves the effective proxyJump
     *
     * @param  originalProxyJump The original requested proxyJump
     * @param  entryProxyJump    The configured host entry proxyJump
     * @return                   If the configured host entry proxyJump is not {@code null}/empty then it is used,
     *                           otherwise the original one.
     */
    public static String resolveProxyJump(String originalProxyJump, String entryProxyJump) {
        if (GenericUtils.isEmpty(entryProxyJump)) {
            return originalProxyJump;
        } else {
            return entryProxyJump;
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
        HostConfigEntry globalEntry = null;
        List<HostConfigEntry> entries = null;

        int lineNumber = 1;
        for (String line = rdr.readLine(); line != null; line = rdr.readLine(), lineNumber++) {
            line = GenericUtils.replaceWhitespaceAndTrim(line);
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

            /*
             * Some options use '=', others use ' ' - try both NOTE: we do not validate the format for each option
             * separately
             */
            pos = line.indexOf(' ');
            if (pos < 0) {
                pos = line.indexOf('=');
            }

            if (pos < 0) {
                throw new StreamCorruptedException("No configuration value delimiter at line " + lineNumber + ": " + line);
            }

            String key = line.substring(0, pos);
            String value = line.substring(pos + 1);
            List<String> valsList = parseConfigValue(value);

            if (HOST_CONFIG_PROP.equalsIgnoreCase(key)) {
                if (GenericUtils.isEmpty(valsList)) {
                    throw new StreamCorruptedException("Missing host pattern(s) at line " + lineNumber + ": " + line);
                }

                // If the all-hosts pattern is used, make sure no global section already active
                for (String name : valsList) {
                    if (ALL_HOSTS_PATTERN.equalsIgnoreCase(name) && (globalEntry != null)) {
                        throw new StreamCorruptedException(
                                "Overriding the global section with a specific one at line " + lineNumber + ": " + line);
                    }
                }

                if (curEntry != null) {
                    curEntry.processGlobalValues(globalEntry);
                }

                entries = updateEntriesList(entries, curEntry);

                curEntry = new HostConfigEntry();
                curEntry.setHost(valsList);
            } else if (curEntry == null) {
                // if 1st encountered property is NOT for a specific host, then configuration applies to ALL
                curEntry = new HostConfigEntry();
                curEntry.setHost(Collections.singletonList(ALL_HOSTS_PATTERN));
                globalEntry = curEntry;
            }

            try {
                curEntry.processProperty(key, valsList, false);
            } catch (RuntimeException e) {
                throw new StreamCorruptedException(
                        "Failed (" + e.getClass().getSimpleName() + ")"
                                                   + " to process line #" + lineNumber + " (" + line + ")"
                                                   + ": " + e.getMessage());
            }
        }

        if (curEntry != null) {
            curEntry.processGlobalValues(globalEntry);
        }

        entries = updateEntriesList(entries, curEntry);
        if (entries == null) {
            return Collections.emptyList();
        } else {
            return entries;
        }
    }

    /**
     * Finds the best match out of the given ones.
     *
     * @param  matches The available matches - ignored if {@code null}/empty
     * @return         The best match or {@code null} if no matches or no best match found
     * @see            #findBestMatch(Iterator)
     */
    public static HostConfigEntry findBestMatch(Collection<? extends HostConfigEntry> matches) {
        if (GenericUtils.isEmpty(matches)) {
            return null;
        } else {
            return findBestMatch(matches.iterator());
        }
    }

    /**
     * Finds the best match out of the given ones.
     *
     * @param  matches The available matches - ignored if {@code null}/empty
     * @return         The best match or {@code null} if no matches or no best match found
     * @see            #findBestMatch(Iterator)
     */
    public static HostConfigEntry findBestMatch(Iterable<? extends HostConfigEntry> matches) {
        if (matches == null) {
            return null;
        } else {
            return findBestMatch(matches.iterator());
        }
    }

    /**
     * Finds the best match out of the given ones. The best match is defined as one whose pattern is as <U>specific</U>
     * as possible (if more than one match is available). I.e., a non-global match is preferred over global one, and a
     * match with no wildcards is preferred over one with such a pattern.
     *
     * @param  matches The available matches - ignored if {@code null}/empty
     * @return         The best match or {@code null} if no matches or no best match found
     * @see            #isSpecificHostPattern(String)
     */
    public static HostConfigEntry findBestMatch(Iterator<? extends HostConfigEntry> matches) {
        if ((matches == null) || (!matches.hasNext())) {
            return null;
        }

        HostConfigEntry candidate = matches.next();
        int wildcardMatches = 0;
        while (matches.hasNext()) {
            HostConfigEntry entry = matches.next();
            String entryPattern = entry.getHost();
            String candidatePattern = candidate.getHost();
            // prefer non-global entry over global entry
            if (ALL_HOSTS_PATTERN.equalsIgnoreCase(candidatePattern)) {
                // unlikely, but handle it
                if (ALL_HOSTS_PATTERN.equalsIgnoreCase(entryPattern)) {
                    wildcardMatches++;
                } else {
                    candidate = entry;
                    wildcardMatches = 0;
                }
                continue;
            }

            if (isSpecificHostPattern(entryPattern)) {
                // if both are specific then no best match
                if (isSpecificHostPattern(candidatePattern)) {
                    return null;
                }

                candidate = entry;
                wildcardMatches = 0;
                continue;
            }

            wildcardMatches++;
        }

        String candidatePattern = candidate.getHost();
        // best match either has specific host or no wildcard matches
        if ((wildcardMatches <= 0) || (isSpecificHostPattern(candidatePattern))) {
            return candidate;
        }

        return null;
    }

    public static List<HostConfigEntry> updateEntriesList(List<HostConfigEntry> entries, HostConfigEntry curEntry) {
        if (curEntry == null) {
            return entries;
        }

        if (entries == null) {
            entries = new ArrayList<>();
        }

        entries.add(curEntry);
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
                if (ch == HOME_TILDE_CHAR) {
                    ValidateUtils.checkTrue((curPos == 0) && (index == 0), "Home tilde must be first: %s", id);
                    appendUserHome(sb);
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
                            appendUserHome(sb);
                            break;
                        case LOCAL_USER_MACRO:
                            sb.append(ValidateUtils.checkNotNullAndNotEmpty(OsUtils.getCurrentUser(),
                                    "No local user name value"));
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
                            sb.append(ValidateUtils.checkNotNullAndNotEmpty(username, "No remote user provided"));
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

    public static StringBuilder appendUserHome(StringBuilder sb) {
        return appendUserHome(sb, IdentityUtils.getUserHomeFolder());
    }

    public static StringBuilder appendUserHome(StringBuilder sb, Path userHome) {
        return appendUserHome(sb, Objects.requireNonNull(userHome, "No user home folder").toString());
    }

    public static StringBuilder appendUserHome(StringBuilder sb, String userHome) {
        if (GenericUtils.isEmpty(userHome)) {
            return sb;
        }

        sb.append(userHome);
        // strip any ending separator since we add our own
        int len = sb.length();
        if (sb.charAt(len - 1) == File.separatorChar) {
            sb.setLength(len - 1);
        }

        return sb;
    }

    /**
     * @return The default {@link Path} location of the OpenSSH hosts entries configuration file
     */
    @SuppressWarnings("synthetic-access")
    public static Path getDefaultHostConfigFile() {
        return LazyDefaultConfigFileHolder.CONFIG_FILE;
    }
}
