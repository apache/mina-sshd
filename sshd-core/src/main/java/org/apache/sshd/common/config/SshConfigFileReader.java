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

package org.apache.sshd.common.config;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
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
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.ClientBuilder;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.common.BuiltinFactory;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.compression.BuiltinCompressions;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.compression.CompressionFactory;
import org.apache.sshd.common.helpers.AbstractFactoryManager;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.kex.DHFactory;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.mac.BuiltinMacs;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Transformer;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.NoCloseInputStream;
import org.apache.sshd.common.util.io.NoCloseReader;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.ServerBuilder;
import org.apache.sshd.server.SshServer;

/**
 * Reads and interprets some useful configurations from an OpenSSH
 * configuration file.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see <a href="https://www.freebsd.org/cgi/man.cgi?query=ssh_config&sektion=5">ssh_config(5)</a>
 */
public final class SshConfigFileReader {

    public static final char COMMENT_CHAR = '#';

    // Some well known configuration properties names and values
    public static final String BANNER_CONFIG_PROP = "Banner";
    public static final String COMPRESSION_PROP = "Compression";
    public static final String DEFAULT_COMPRESSION = CompressionConfigValue.NO.getName();
    public static final String ALLOW_TCP_FORWARDING_CONFIG_PROP = "AllowTcpForwarding";
    public static final String DEFAULT_TCP_FORWARDING = "yes";
    public static final boolean DEFAULT_TCP_FORWARDING_VALUE = parseBooleanValue(DEFAULT_TCP_FORWARDING);
    public static final String ALLOW_AGENT_FORWARDING_CONFIG_PROP = "AllowAgentForwarding";
    public static final String DEFAULT_AGENT_FORWARDING = "yes";
    public static final boolean DEFAULT_AGENT_FORWARDING_VALUE = parseBooleanValue(DEFAULT_AGENT_FORWARDING);
    public static final String ALLOW_X11_FORWARDING_CONFIG_PROP = "X11Forwarding";
    public static final String DEFAULT_X11_FORWARDING = "yes";
    public static final boolean DEFAULT_X11_FORWARDING_VALUE = parseBooleanValue(DEFAULT_X11_FORWARDING);
    public static final String MAX_SESSIONS_CONFIG_PROP = "MaxSessions";
    public static final int DEFAULT_MAX_SESSIONS = 10;
    public static final String PASSWORD_AUTH_CONFIG_PROP = "PasswordAuthentication";
    public static final String DEFAULT_PASSWORD_AUTH = "no";
    public static final boolean DEFAULT_PASSWORD_AUTH_VALUE = parseBooleanValue(DEFAULT_PASSWORD_AUTH);
    public static final String LISTEN_ADDRESS_CONFIG_PROP = "ListenAddress";
    public static final String DEFAULT_BIND_ADDRESS = SshdSocketAddress.IP_ANYADDR;
    public static final String PORT_CONFIG_PROP = "Port";
    public static final int DEFAULT_PORT = 22;
    public static final String KEEP_ALIVE_CONFIG_PROP = "TCPKeepAlive";
    public static final boolean DEFAULT_KEEP_ALIVE = true;
    public static final String USE_DNS_CONFIG_PROP = "UseDNS";
    // NOTE: the usual default is TRUE
    public static final boolean DEFAULT_USE_DNS = true;
    public static final String PUBKEY_AUTH_CONFIG_PROP = "PubkeyAuthentication";
    public static final String DEFAULT_PUBKEY_AUTH = "yes";
    public static final boolean DEFAULT_PUBKEY_AUTH_VALUE = parseBooleanValue(DEFAULT_PUBKEY_AUTH);
    public static final String AUTH_KEYS_FILE_CONFIG_PROP = "AuthorizedKeysFile";
    public static final String MAX_AUTH_TRIES_CONFIG_PROP = "MaxAuthTries";
    public static final int DEFAULT_MAX_AUTH_TRIES = 6;
    public static final String MAX_STARTUPS_CONFIG_PROP = "MaxStartups";
    public static final int DEFAULT_MAX_STARTUPS = 10;
    public static final String LOGIN_GRACE_TIME_CONFIG_PROP = "LoginGraceTime";
    public static final long DEFAULT_LOGIN_GRACE_TIME = TimeUnit.SECONDS.toMillis(120);
    public static final String KEY_REGENERATE_INTERVAL_CONFIG_PROP = "KeyRegenerationInterval";
    public static final long DEFAULT_REKEY_TIME_LIMIT = TimeUnit.HOURS.toMillis(1L);
    // see http://manpages.ubuntu.com/manpages/precise/en/man5/sshd_config.5.html
    public static final String CIPHERS_CONFIG_PROP = "Ciphers";
    public static final String DEFAULT_CIPHERS =
            "aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour";
    // see http://manpages.ubuntu.com/manpages/precise/en/man5/sshd_config.5.html
    public static final String MACS_CONFIG_PROP = "MACs";
    public static final String DEFAULT_MACS =
            "hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-ripemd160,hmac-sha1-96,hmac-md5-96,hmac-sha2-256,hmac-sha2-256-96,hmac-sha2-512,hmac-sha2-512-96";
    // see http://manpages.ubuntu.com/manpages/precise/en/man5/sshd_config.5.html
    public static final String KEX_ALGORITHMS_CONFIG_PROP = "KexAlgorithms";
    public static final String DEFAULT_KEX_ALGORITHMS =
            "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521"
                    + "," + "diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1"
                    + "," + "diffie-hellman-group14-sha1,diffie-hellman-group1-sha1";
    // see http://linux.die.net/man/5/ssh_config
    public static final String HOST_KEY_ALGORITHMS_CONFIG_PROP = "HostKeyAlgorithms";
    // see https://tools.ietf.org/html/rfc5656
    public static final String DEFAULT_HOST_KEY_ALGORITHMS =
            KeyPairProvider.SSH_RSA
                    + "," + KeyPairProvider.SSH_DSS;
    // see http://manpages.ubuntu.com/manpages/precise/en/man5/sshd_config.5.html
    public static final String LOG_LEVEL_CONFIG_PROP = "LogLevel";
    public static final LogLevelValue DEFAULT_LOG_LEVEL = LogLevelValue.INFO;
    // see https://www.freebsd.org/cgi/man.cgi?query=sshd_config&sektion=5
    public static final String SYSLOG_FACILITY_CONFIG_PROP = "SyslogFacility";
    public static final SyslogFacilityValue DEFAULT_SYSLOG_FACILITY = SyslogFacilityValue.AUTH;
    public static final String SUBSYSTEM_CONFIG_PROP = "Subsystem";

    private SshConfigFileReader() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    public static Properties readConfigFile(File file) throws IOException {
        return readConfigFile(file.toPath(), IoUtils.EMPTY_OPEN_OPTIONS);
    }

    public static Properties readConfigFile(Path path, OpenOption... options) throws IOException {
        try (InputStream input = Files.newInputStream(path, options)) {
            return readConfigFile(input, true);
        }
    }

    public static Properties readConfigFile(URL url) throws IOException {
        try (InputStream input = url.openStream()) {
            return readConfigFile(input, true);
        }
    }

    public static Properties readConfigFile(String path) throws IOException {
        try (InputStream input = new FileInputStream(path)) {
            return readConfigFile(input, true);
        }
    }

    public static Properties readConfigFile(InputStream input, boolean okToClose) throws IOException {
        try (Reader reader = new InputStreamReader(NoCloseInputStream.resolveInputStream(input, okToClose), StandardCharsets.UTF_8)) {
            return readConfigFile(reader, true);
        }
    }

    public static Properties readConfigFile(Reader reader, boolean okToClose) throws IOException {
        try (BufferedReader buf = new BufferedReader(NoCloseReader.resolveReader(reader, okToClose))) {
            return readConfigFile(buf);
        }
    }

    /**
     * Reads the configuration file contents into a {@link Properties} instance.
     * <B>Note:</B> multiple keys value are concatenated using a comma - it is up to
     * the caller to know which keys are expected to have multiple values and handle
     * the split accordingly
     *
     * @param rdr The {@link BufferedReader} for reading the file
     * @return The read properties
     * @throws IOException If failed to read or malformed content
     */
    public static Properties readConfigFile(BufferedReader rdr) throws IOException {
        Properties props = new Properties();
        int lineNumber = 1;
        for (String line = rdr.readLine(); line != null; line = rdr.readLine(), lineNumber++) {
            line = GenericUtils.trimToEmpty(line);
            if (GenericUtils.isEmpty(line)) {
                continue;
            }

            int pos = line.indexOf(COMMENT_CHAR);
            if (pos == 0) {
                continue;
            }

            if (pos > 0) {
                line = line.substring(0, pos);
                line = line.trim();
            }

            /*
             * Some options use '=', others use ' ' - try both
             * NOTE: we do not validate the format for each option separately
             */
            pos = line.indexOf(' ');
            if (pos < 0) {
                pos = line.indexOf('=');
            }

            if (pos < 0) {
                throw new StreamCorruptedException("No delimiter at line " + lineNumber + ": " + line);
            }

            String key = line.substring(0, pos);
            String value = line.substring(pos + 1).trim();
            // see if need to concatenate multi-valued keys
            String prev = props.getProperty(key);
            if (!GenericUtils.isEmpty(prev)) {
                value = prev + "," + value;
            }

            props.setProperty(key, value);
        }

        return props;
    }

    /**
     * @param props        The {@link Properties} - ignored if {@code null}/empty
     * @param name         The property name
     * @param defaultValue The default value to return if the specified property
     *                     does not exist in the properties map or is an empty string
     * @return The resolved property
     * @throws NumberFormatException if malformed value
     */
    public static long getLongProperty(Properties props, String name, long defaultValue) {
        String value = (props == null) ? null : props.getProperty(name);
        if (GenericUtils.isEmpty(value)) {
            return defaultValue;
        } else {
            return Long.parseLong(value);
        }
    }

    /**
     * @param props The {@link Properties} - ignored if {@code null}/empty
     * @param name  The property name
     * @return The {@link Long} value or {@code null} if property not found or
     * empty string
     * @throws NumberFormatException if malformed value
     */
    public static Long getLong(Properties props, String name) {
        String value = (props == null) ? null : props.getProperty(name);
        if (GenericUtils.isEmpty(value)) {
            return null;
        } else {
            return Long.valueOf(value);
        }
    }

    /**
     * @param props        The {@link Properties} - ignored if {@code null}/empty
     * @param name         The property name
     * @param defaultValue The default value to return if the specified property
     *                     does not exist in the properties map or is an empty string
     * @return The resolved property
     * @throws NumberFormatException if malformed value
     */
    public static int getIntProperty(Properties props, String name, int defaultValue) {
        String value = (props == null) ? null : props.getProperty(name);
        if (GenericUtils.isEmpty(value)) {
            return defaultValue;
        } else {
            return Integer.parseInt(value);
        }
    }

    /**
     * @param props The {@link Properties} - ignored if {@code null}/empty
     * @param name  The property name
     * @return The {@link Integer} value or {@code null} if property not found or
     * empty string
     * @throws NumberFormatException if malformed value
     */
    public static Integer getInteger(Properties props, String name) {
        String value = (props == null) ? null : props.getProperty(name);
        if (GenericUtils.isEmpty(value)) {
            return null;
        } else {
            return Integer.valueOf(value);
        }
    }

    /**
     * @param props        The {@link Properties} - ignored if {@code null}/empty
     * @param name         The property name
     * @param defaultValue The default value to return if the specified property
     *                     does not exist in the properties map or is an empty string
     * @return The resolved property
     * @throws NumberFormatException if malformed value
     */
    public static boolean getBooleanProperty(Properties props, String name, boolean defaultValue) {
        String value = (props == null) ? null : props.getProperty(name);
        if (GenericUtils.isEmpty(value)) {
            return defaultValue;
        } else {
            return parseBooleanValue(value);
        }
    }

    /**
     * @param props The {@link Properties} - ignored if {@code null}/empty
     * @param name  The property name
     * @return The {@link Boolean} value or {@code null} if property not found or
     * empty string
     * @throws NumberFormatException if malformed value
     */
    public static Boolean getBoolean(Properties props, String name) {
        String value = (props == null) ? null : props.getProperty(name);
        if (GenericUtils.isEmpty(value)) {
            return null;
        } else {
            return parseBooleanValue(value);
        }
    }

    /**
     * @param v            The value to parse - if {@code null}/empty then the default
     *                     value is returned, otherwise {@link #parseBooleanValue(String)} is used
     * @param defaultValue The default value to return if {@code null}/empty
     *                     input string
     * @return The result
     */
    public static boolean parseBooleanValue(String v, boolean defaultValue) {
        if (GenericUtils.isEmpty(v)) {
            return defaultValue;
        } else {
            return parseBooleanValue(v);
        }
    }

    /**
     * @param v Checks if the value is &quot;yes&quot;, &quot;y&quot;
     *          or &quot;on&quot; or &quot;true&quot;.
     * @return The result - <B>Note:</B> {@code null}/empty values are
     * intrepreted as {@code false}
     */
    public static boolean parseBooleanValue(String v) {
        return "yes".equalsIgnoreCase(v)
                || "y".equalsIgnoreCase(v)
                || "on".equalsIgnoreCase(v)
                || "true".equalsIgnoreCase(v);
    }

    /**
     * Returns a &quot;yes&quot; or &quot;no&quot; value based on the input
     * parameter
     *
     * @param flag The required state
     * @return &quot;yes&quot; if {@code true}, &quot;no&quot; otherwise
     */
    public static String yesNoValueOf(boolean flag) {
        return flag ? "yes" : "no";
    }

    /**
     * @param props The {@link Properties} - ignored if {@code null}/empty
     * @return A {@code ParseResult} of all the {@link NamedFactory}-ies
     * whose name appears in the string and represent a built-in cipher.
     * Any unknown name is <U>ignored</U>. The order of the returned result
     * is the same as the original order - bar the unknown ciphers.
     * <B>Note:</B> it is up to caller to ensure that the lists do not
     * contain duplicates
     * @see #CIPHERS_CONFIG_PROP
     * @see BuiltinCiphers#parseCiphersList(String)
     */
    public static BuiltinCiphers.ParseResult getCiphers(Properties props) {
        return BuiltinCiphers.parseCiphersList((props == null) ? null : props.getProperty(CIPHERS_CONFIG_PROP));
    }

    /**
     * @param props The {@link Properties} - ignored if {@code null}/empty
     * @return A {@code ParseResult} of all the {@link NamedFactory}-ies
     * whose name appears in the string and represent a built-in MAC. Any
     * unknown name is <U>ignored</U>. The order of the returned result
     * is the same as the original order - bar the unknown MACs.
     * <B>Note:</B> it is up to caller to ensure that the list does not
     * contain duplicates
     * @see #MACS_CONFIG_PROP
     * @see BuiltinMacs#parseMacsList(String)
     */
    public static BuiltinMacs.ParseResult getMacs(Properties props) {
        return BuiltinMacs.parseMacsList((props == null) ? null : props.getProperty(MACS_CONFIG_PROP));
    }

    /**
     * @param props The {@link Properties} - ignored if {@code null}/empty
     * @return A {@code ParseResult} of all the {@link NamedFactory}
     * whose name appears in the string and represent a built-in signature. Any
     * unknown name is <U>ignored</U>. The order of the returned result is the
     * same as the original order - bar the unknown signatures. <B>Note:</B> it
     * is up to caller to ensure that the list does not contain duplicates
     * @see #HOST_KEY_ALGORITHMS_CONFIG_PROP
     * @see BuiltinSignatures#parseSignatureList(String)
     */
    public static BuiltinSignatures.ParseResult getSignatures(Properties props) {
        return BuiltinSignatures.parseSignatureList((props == null) ? null : props.getProperty(HOST_KEY_ALGORITHMS_CONFIG_PROP));
    }

    /**
     * @param props The {@link Properties} - ignored if {@code null}/empty
     * @return A {@code ParseResult} of all the {@link DHFactory}-ies
     * whose name appears in the string and represent a built-in value. Any
     * unknown name is <U>ignored</U>. The order of the returned result is the
     * same as the original order - bar the unknown ones. <B>Note:</B> it is
     * up to caller to ensure that the list does not contain duplicates
     * @see #KEX_ALGORITHMS_CONFIG_PROP
     * @see BuiltinDHFactories#parseDHFactoriesList(String)
     */
    public static BuiltinDHFactories.ParseResult getKexFactories(Properties props) {
        return BuiltinDHFactories.parseDHFactoriesList((props == null) ? null : props.getProperty(KEX_ALGORITHMS_CONFIG_PROP));
    }

    /**
     * @param props The {@link Properties} - ignored if {@code null}/empty
     * @return The matching {@link NamedFactory} for the configured value.
     * {@code null} if no configuration or unknown name specified
     */
    public static CompressionFactory getCompression(Properties props) {
        return CompressionConfigValue.fromName((props == null) ? null : props.getProperty(COMPRESSION_PROP));
    }

    public static <S extends SshServer> S configure(S server, Properties props, boolean lenient, boolean ignoreUnsupported) {
        configure((AbstractFactoryManager) server, props, lenient, ignoreUnsupported);
        configureKeyExchanges(server, props, lenient, ServerBuilder.DH2KEX, ignoreUnsupported);
        return server;
    }

    public static <C extends SshClient> C configure(C client, Properties props, boolean lenient, boolean ignoreUnsupported) {
        configure((AbstractFactoryManager) client, props, lenient, ignoreUnsupported);
        configureKeyExchanges(client, props, lenient, ClientBuilder.DH2KEX, ignoreUnsupported);
        return client;
    }

    /**
     * <P>Configures an {@link AbstractFactoryManager} with the values read from
     * some configuration. Currently it configures:</P>
     * <UL>
     * <LI>The {@link Cipher}s - via the {@link #CIPHERS_CONFIG_PROP}</LI>
     * <LI>The {@link Mac}s - via the {@link #MACS_CONFIG_PROP}</LI>
     * <LI>The {@link Signature}s - via the {@link #HOST_KEY_ALGORITHMS_CONFIG_PROP}</LI>
     * <LI>The {@link Compression} - via the {@link #COMPRESSION_PROP}</LI>
     * </UL>
     *
     * @param <M>               The generic factory manager
     * @param manager           The {@link AbstractFactoryManager} to configure
     * @param props             The {@link Properties} to use for configuration - <B>Note:</B>
     *                          if any known configuration value has a default and does not appear in the
     *                          properties, the default is used
     * @param lenient           If {@code true} then any unknown configuration values are ignored.
     *                          Otherwise an {@link IllegalArgumentException} is thrown
     * @param ignoreUnsupported filter out unsupported configuration values (e.g., ciphers,
     *                          key exchanges, etc..). <B>Note:</B> if after filtering out all the unknown
     *                          or unsupported values there is an empty configuration exception is thrown
     * @return The configured manager
     */
    public static <M extends AbstractFactoryManager> M configure(M manager, Properties props, boolean lenient, boolean ignoreUnsupported) {
        configureCiphers(manager, props, lenient, ignoreUnsupported);
        configureSignatures(manager, props, lenient, ignoreUnsupported);
        configureMacs(manager, props, lenient, ignoreUnsupported);
        configureCompression(manager, props, lenient, ignoreUnsupported);

        return manager;
    }

    public static <M extends AbstractFactoryManager> M configureCiphers(M manager, Properties props, boolean lenient, boolean ignoreUnsupported) {
        ValidateUtils.checkNotNull(props, "No properties to configure");
        return configureCiphers(manager, props.getProperty(CIPHERS_CONFIG_PROP, DEFAULT_CIPHERS), lenient, ignoreUnsupported);
    }

    public static <M extends AbstractFactoryManager> M configureCiphers(M manager, String value, boolean lenient, boolean ignoreUnsupported) {
        ValidateUtils.checkNotNull(manager, "No manager to configure");

        BuiltinCiphers.ParseResult result = BuiltinCiphers.parseCiphersList(value);
        Collection<String> unsupported = result.getUnsupportedFactories();
        ValidateUtils.checkTrue(lenient || GenericUtils.isEmpty(unsupported), "Unsupported cipher(s) (%s) in %s", unsupported, value);

        List<NamedFactory<Cipher>> factories =
                BuiltinFactory.Utils.setUpFactories(ignoreUnsupported, result.getParsedFactories());
        manager.setCipherFactories(ValidateUtils.checkNotNullAndNotEmpty(factories, "No known/unsupported ciphers(s): %s", value));
        return manager;
    }

    public static <M extends AbstractFactoryManager> M configureSignatures(M manager, Properties props, boolean lenient, boolean ignoreUnsupported) {
        ValidateUtils.checkNotNull(props, "No properties to configure");
        return configureSignatures(manager, props.getProperty(HOST_KEY_ALGORITHMS_CONFIG_PROP, DEFAULT_HOST_KEY_ALGORITHMS), lenient, ignoreUnsupported);
    }

    public static <M extends AbstractFactoryManager> M configureSignatures(M manager, String value, boolean lenient, boolean ignoreUnsupported) {
        ValidateUtils.checkNotNull(manager, "No manager to configure");

        BuiltinSignatures.ParseResult result = BuiltinSignatures.parseSignatureList(value);
        Collection<String> unsupported = result.getUnsupportedFactories();
        ValidateUtils.checkTrue(lenient || GenericUtils.isEmpty(unsupported), "Unsupported signatures (%s) in %s", unsupported, value);

        List<NamedFactory<Signature>> factories =
                BuiltinFactory.Utils.setUpFactories(ignoreUnsupported, result.getParsedFactories());
        manager.setSignatureFactories(ValidateUtils.checkNotNullAndNotEmpty(factories, "No known/supported signatures: %s", value));
        return manager;
    }

    public static <M extends AbstractFactoryManager> M configureMacs(M manager, Properties props, boolean lenient, boolean ignoreUnsupported) {
        ValidateUtils.checkNotNull(props, "No properties to configure");
        return configureMacs(manager, props.getProperty(MACS_CONFIG_PROP, DEFAULT_MACS), lenient, ignoreUnsupported);
    }

    public static <M extends AbstractFactoryManager> M configureMacs(M manager, String value, boolean lenient, boolean ignoreUnsupported) {
        ValidateUtils.checkNotNull(manager, "No manager to configure");

        BuiltinMacs.ParseResult result = BuiltinMacs.parseMacsList(value);
        Collection<String> unsupported = result.getUnsupportedFactories();
        ValidateUtils.checkTrue(lenient || GenericUtils.isEmpty(unsupported), "Unsupported MAC(s) (%s) in %s", unsupported, value);

        List<NamedFactory<Mac>> factories =
                BuiltinFactory.Utils.setUpFactories(ignoreUnsupported, result.getParsedFactories());
        manager.setMacFactories(ValidateUtils.checkNotNullAndNotEmpty(factories, "No known/supported MAC(s): %s", value));
        return manager;
    }

    /**
     * @param <M>               The generic factory manager
     * @param manager           The {@link AbstractFactoryManager} to set up (may not be {@code null})
     * @param props             The (non-{@code null}) {@link Properties} containing the configuration
     * @param lenient           If {@code true} then any unknown/unsupported configuration
     *                          values are ignored. Otherwise an {@link IllegalArgumentException} is thrown
     * @param xformer           A {@link Transformer} to convert the configured {@link DHFactory}-ies
     *                          to {@link NamedFactory}-ies of {@link KeyExchange}
     * @param ignoreUnsupported Filter out any un-supported configurations - <B>Note:</B>
     *                          if after ignoring the unknown and un-supported values the result is an empty
     *                          list of factories and exception is thrown
     * @return The configured manager
     * @see #KEX_ALGORITHMS_CONFIG_PROP
     * @see #DEFAULT_KEX_ALGORITHMS
     */
    public static <M extends AbstractFactoryManager> M configureKeyExchanges(
            M manager, Properties props, boolean lenient, Transformer<? super DHFactory, ? extends NamedFactory<KeyExchange>> xformer, boolean ignoreUnsupported) {
        ValidateUtils.checkNotNull(props, "No properties to configure");
        return configureKeyExchanges(manager, props.getProperty(KEX_ALGORITHMS_CONFIG_PROP, DEFAULT_KEX_ALGORITHMS), lenient, xformer, ignoreUnsupported);
    }

    public static <M extends AbstractFactoryManager> M configureKeyExchanges(
            M manager, String value, boolean lenient, Transformer<? super DHFactory, ? extends NamedFactory<KeyExchange>> xformer, boolean ignoreUnsupported) {
        ValidateUtils.checkNotNull(manager, "No manager to configure");
        ValidateUtils.checkNotNull(xformer, "No DHFactory transformer");

        BuiltinDHFactories.ParseResult result = BuiltinDHFactories.parseDHFactoriesList(value);
        Collection<String> unsupported = result.getUnsupportedFactories();
        ValidateUtils.checkTrue(lenient || GenericUtils.isEmpty(unsupported), "Unsupported KEX(s) (%s) in %s", unsupported, value);

        List<NamedFactory<KeyExchange>> factories =
                NamedFactory.Utils.setUpTransformedFactories(ignoreUnsupported, result.getParsedFactories(), xformer);
        manager.setKeyExchangeFactories(ValidateUtils.checkNotNullAndNotEmpty(factories, "No known/supported KEXS(s): %s", value));
        return manager;
    }

    /**
     * Configure the factory manager using one of the known {@link CompressionConfigValue}s.
     *
     * @param <M>               The generic factory manager
     * @param manager           The {@link AbstractFactoryManager} to configure
     * @param props             The configuration {@link Properties}
     * @param lenient           If {@code true} and an unknown value is provided then
     *                          it is ignored
     * @param ignoreUnsupported If {@code false} then check if the compression
     *                          is currently supported before setting it
     * @return The configured manager - <B>Note:</B> if the result of filtering due
     * to lenient mode or ignored unsupported value is empty then no factories are set
     */
    public static <M extends AbstractFactoryManager> M configureCompression(M manager, Properties props, boolean lenient, boolean ignoreUnsupported) {
        ValidateUtils.checkNotNull(manager, "No manager to configure");
        ValidateUtils.checkNotNull(props, "No properties to configure");

        String value = props.getProperty(COMPRESSION_PROP, DEFAULT_COMPRESSION);
        CompressionFactory factory = CompressionConfigValue.fromName(value);
        ValidateUtils.checkTrue(lenient || (factory != null), "Unsupported compression value: %s", value);
        if ((factory != null) && factory.isSupported()) {
            manager.setCompressionFactories(Collections.<NamedFactory<Compression>>singletonList(factory));
        }

        return manager;
    }

    // accepts BOTH CompressionConfigValue(s) and/or BuiltinCompressions - including extensions
    public static <M extends AbstractFactoryManager> M configureCompression(M manager, String value, boolean lenient, boolean ignoreUnsupported) {
        ValidateUtils.checkNotNull(manager, "No manager to configure");

        CompressionFactory factory = CompressionConfigValue.fromName(value);
        if (factory != null) {
            // SSH can work without compression
            if (ignoreUnsupported || factory.isSupported()) {
                manager.setCompressionFactories(Collections.<NamedFactory<Compression>>singletonList(factory));
            }
        } else {
            BuiltinCompressions.ParseResult result = BuiltinCompressions.parseCompressionsList(value);
            Collection<String> unsupported = result.getUnsupportedFactories();
            ValidateUtils.checkTrue(lenient || GenericUtils.isEmpty(unsupported), "Unsupported compressions(s) (%s) in %s", unsupported, value);

            List<NamedFactory<Compression>> factories =
                    BuiltinFactory.Utils.setUpFactories(ignoreUnsupported, result.getParsedFactories());
            // SSH can work without compression
            if (GenericUtils.size(factories) > 0) {
                manager.setCompressionFactories(factories);
            }
        }

        return manager;
    }
}
