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
package org.apache.sshd.server.config;

import java.nio.file.Paths;
import java.time.Duration;
import java.util.Map;

import org.apache.sshd.common.Property;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.config.ConfigFileReaderSupport;
import org.apache.sshd.common.config.SshConfigFileReader;
import org.apache.sshd.common.session.SessionHeartbeatController.HeartbeatType;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.ServerBuilder;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.forward.AgentForwardingFilter;
import org.apache.sshd.server.forward.ForwardingFilter;
import org.apache.sshd.server.forward.TcpForwardingFilter;
import org.apache.sshd.server.forward.X11ForwardingFilter;

/**
 * Reads and interprets some useful configurations from an OpenSSH configuration file.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <a href="http://www.freebsd.org/cgi/man.cgi?query=sshd_config&sektion=5">sshd_config(5)</a>
 */
public final class SshServerConfigFileReader {
    // Some well known configuration properties names and values
    public static final Property<String> ALLOW_TCP_FORWARDING_CONFIG_PROP = Property.string("AllowTcpForwarding", "yes");

    public static final Property<String> ALLOW_AGENT_FORWARDING_CONFIG_PROP = Property.string("AllowAgentForwarding", "yes");

    public static final Property<String> ALLOW_X11_FORWARDING_CONFIG_PROP = Property.string("X11Forwarding", "no");

    public static final Property<String> BANNER_CONFIG_PROP = Property.string("Banner");

    public static final Property<String> VISUAL_HOST_KEY = Property.string("VisualHostKey", "no");

    public static final Property<Duration> SERVER_ALIVE_INTERVAL_PROP = Property.duration("ServerAliveInterval");

    public static final Property<Integer> SFTP_FORCED_VERSION_PROP = Property.integer("sftp-version");

    private SshServerConfigFileReader() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    public static <S extends ServerFactoryManager> S setupServerHeartbeat(S server, PropertyResolver props) {
        if ((server == null) || (props == null)) {
            return server;
        }

        Duration interval = SERVER_ALIVE_INTERVAL_PROP.getOrNull(props);
        if (interval == null || GenericUtils.isNegativeOrNull(interval)) {
            return server;
        }

        server.setSessionHeartbeat(HeartbeatType.IGNORE, interval);
        return server;
    }

    public static <S extends ServerFactoryManager> S setupServerHeartbeat(S server, Map<String, ?> options) {
        if ((server == null) || GenericUtils.isEmpty(options)) {
            return server;
        }

        return setupServerHeartbeat(server, PropertyResolverUtils.toPropertyResolver(options));
    }

    public static <S extends ServerFactoryManager> S setupSftpSubsystem(S server, PropertyResolver props) {
        if ((server == null) || (props == null)) {
            return server;
        }

        Integer version = SFTP_FORCED_VERSION_PROP.getOrNull(props);
        if (version != null && version >= 0) {
            SFTP_FORCED_VERSION_PROP.set(server, version);
        }

        return server;
    }

    public static <S extends SshServer> S configure(
            S server, PropertyResolver props, boolean lenient, boolean ignoreUnsupported) {
        SshConfigFileReader.configure(server, props, lenient, ignoreUnsupported);
        SshConfigFileReader.configureKeyExchanges(server, props, lenient, ServerBuilder.DH2KEX, ignoreUnsupported);
        setupServerHeartbeat(server, props);
        return server;
    }

    public static ForwardingFilter resolveServerForwarding(PropertyResolver options) {
        if (GenericUtils.isEmpty(options)) {
            return AcceptAllForwardingFilter.INSTANCE;
        }

        AgentForwardingFilter agentFilter = resolveAgentForwardingFilter(options);
        TcpForwardingFilter tcpFilter = resolveTcpForwardingFilter(options);
        X11ForwardingFilter x11Filter = resolveX11ForwardingFilter(options);
        return ForwardingFilter.asForwardingFilter(agentFilter, x11Filter, tcpFilter);
    }

    public static AgentForwardingFilter resolveAgentForwardingFilter(PropertyResolver options) {
        String value = ALLOW_AGENT_FORWARDING_CONFIG_PROP.getRequired(options);
        return AgentForwardingFilter.of(ConfigFileReaderSupport.parseBooleanValue(value));
    }

    public static TcpForwardingFilter resolveTcpForwardingFilter(PropertyResolver options) {
        String value = ALLOW_TCP_FORWARDING_CONFIG_PROP.getRequired(options);
        TcpForwardingFilter filter = AllowTcpForwardingValue.fromString(value);
        ValidateUtils.checkNotNull(filter, "Unknown %s value: %s", ALLOW_TCP_FORWARDING_CONFIG_PROP, value);
        return filter;
    }

    public static X11ForwardingFilter resolveX11ForwardingFilter(PropertyResolver options) {
        String value = ALLOW_X11_FORWARDING_CONFIG_PROP.getRequired(options);
        return X11ForwardingFilter.of(ConfigFileReaderSupport.parseBooleanValue(value));
    }

    public static Object resolveBanner(PropertyResolver options) {
        String bannerOption = BANNER_CONFIG_PROP.getOrNull(options);
        if (GenericUtils.isEmpty(bannerOption)) {
            bannerOption = VISUAL_HOST_KEY.getRequired(options);
            if (ConfigFileReaderSupport.parseBooleanValue(bannerOption)) {
                bannerOption = CoreModuleProperties.AUTO_WELCOME_BANNER_VALUE;
            } else {
                bannerOption = null;
            }
        }

        if (GenericUtils.isEmpty(bannerOption)) {
            return "Welcome to SSHD\n";
        } else if (PropertyResolverUtils.isNoneValue(bannerOption)) {
            return null;
        } else if (CoreModuleProperties.AUTO_WELCOME_BANNER_VALUE.equalsIgnoreCase(bannerOption)) {
            return bannerOption;
        } else if (bannerOption != null) {
            return Paths.get(bannerOption);
        } else {
            return null;
        }
    }
}
