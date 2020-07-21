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
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.NoCloseInputStream;
import org.apache.sshd.common.util.io.NoCloseReader;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <a href="https://www.freebsd.org/cgi/man.cgi?query=ssh_config&sektion=5">ssh_config(5)</a>
 */
public final class ConfigFileReaderSupport {

    public static final char COMMENT_CHAR = '#';

    public static final String COMPRESSION_PROP = "Compression";
    public static final String DEFAULT_COMPRESSION = CompressionConfigValue.NO.getName();
    public static final String MAX_SESSIONS_CONFIG_PROP = "MaxSessions";
    public static final int DEFAULT_MAX_SESSIONS = 10;

    public static final String PUBKEY_AUTH_CONFIG_PROP = "PubkeyAuthentication";
    public static final String DEFAULT_PUBKEY_AUTH = "yes";
    public static final boolean DEFAULT_PUBKEY_AUTH_VALUE = parseBooleanValue(DEFAULT_PUBKEY_AUTH);

    public static final String PASSWORD_AUTH_CONFIG_PROP = "PasswordAuthentication";
    public static final String DEFAULT_PASSWORD_AUTH = "yes";
    public static final boolean DEFAULT_PASSWORD_AUTH_VALUE = parseBooleanValue(DEFAULT_PASSWORD_AUTH);

    public static final String KBD_INTERACTIVE_CONFIG_PROP = "KbdInteractiveAuthentication";
    public static final String DEFAULT_KBD_INTERACTIVE_AUTH = "yes";
    public static final boolean DEFAULT_KBD_INTERACTIVE_AUTH_VALUE = parseBooleanValue(DEFAULT_KBD_INTERACTIVE_AUTH);

    public static final String PREFERRED_AUTHS_CONFIG_PROP = "PreferredAuthentications";

    public static final String LISTEN_ADDRESS_CONFIG_PROP = "ListenAddress";
    public static final String DEFAULT_BIND_ADDRESS = SshdSocketAddress.IPV4_ANYADDR;
    public static final String PORT_CONFIG_PROP = "Port";
    public static final String KEEP_ALIVE_CONFIG_PROP = "TCPKeepAlive";
    public static final boolean DEFAULT_KEEP_ALIVE = true;
    public static final String USE_DNS_CONFIG_PROP = "UseDNS";
    // NOTE: the usual default is TRUE
    public static final boolean DEFAULT_USE_DNS = true;
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
    // see http://manpages.ubuntu.com/manpages/precise/en/man5/sshd_config.5.html
    public static final String MACS_CONFIG_PROP = "MACs";
    // see http://manpages.ubuntu.com/manpages/precise/en/man5/sshd_config.5.html
    public static final String KEX_ALGORITHMS_CONFIG_PROP = "KexAlgorithms";
    // see http://linux.die.net/man/5/ssh_config
    public static final String HOST_KEY_ALGORITHMS_CONFIG_PROP = "HostKeyAlgorithms";
    // see http://manpages.ubuntu.com/manpages/precise/en/man5/sshd_config.5.html
    public static final String LOG_LEVEL_CONFIG_PROP = "LogLevel";
    public static final LogLevelValue DEFAULT_LOG_LEVEL = LogLevelValue.INFO;
    // see https://www.freebsd.org/cgi/man.cgi?query=sshd_config&sektion=5
    public static final String SYSLOG_FACILITY_CONFIG_PROP = "SyslogFacility";
    public static final SyslogFacilityValue DEFAULT_SYSLOG_FACILITY = SyslogFacilityValue.AUTH;
    public static final String SUBSYSTEM_CONFIG_PROP = "Subsystem";

    private ConfigFileReaderSupport() {
        throw new UnsupportedOperationException("No instance");
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

    public static Properties readConfigFile(InputStream input, boolean okToClose) throws IOException {
        try (Reader reader = new InputStreamReader(
                NoCloseInputStream.resolveInputStream(input, okToClose), StandardCharsets.UTF_8)) {
            return readConfigFile(reader, true);
        }
    }

    public static Properties readConfigFile(Reader reader, boolean okToClose) throws IOException {
        try (BufferedReader buf = new BufferedReader(NoCloseReader.resolveReader(reader, okToClose))) {
            return readConfigFile(buf);
        }
    }

    /**
     * Reads the configuration file contents into a {@link Properties} instance. <B>Note:</B> multiple keys value are
     * concatenated using a comma - it is up to the caller to know which keys are expected to have multiple values and
     * handle the split accordingly
     *
     * @param  rdr         The {@link BufferedReader} for reading the file
     * @return             The read properties
     * @throws IOException If failed to read or malformed content
     */
    public static Properties readConfigFile(BufferedReader rdr) throws IOException {
        Properties props = new Properties();
        int lineNumber = 1;
        for (String line = rdr.readLine(); line != null; line = rdr.readLine(), lineNumber++) {
            line = GenericUtils.replaceWhitespaceAndTrim(line);
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
             * Some options use '=', others use ' ' - try both NOTE: we do not validate the format for each option
             * separately
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
     * @param  v Checks if the value is &quot;yes&quot;, &quot;y&quot;, &quot;on&quot;, &quot;t&quot; or
     *           &quot;true&quot;.
     * @return   The result - <B>Note:</B> {@code null}/empty values are interpreted as {@code false}
     * @see      PropertyResolverUtils#TRUE_VALUES
     */
    public static boolean parseBooleanValue(String v) {
        if (GenericUtils.isEmpty(v)) {
            return false;
        }

        return PropertyResolverUtils.TRUE_VALUES.contains(v);
    }

    /**
     * Returns a &quot;yes&quot; or &quot;no&quot; value based on the input parameter
     *
     * @param  flag The required state
     * @return      &quot;yes&quot; if {@code true}, &quot;no&quot; otherwise
     */
    public static String yesNoValueOf(boolean flag) {
        return flag ? "yes" : "no";
    }
}
