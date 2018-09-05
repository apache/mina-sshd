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

import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.config.ConfigFileReaderSupport;
import org.apache.sshd.common.config.SshConfigFileReader;
import org.apache.sshd.common.helpers.AbstractFactoryManager;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.server.ServerAuthenticationManager;
import org.apache.sshd.server.ServerBuilder;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.forward.AgentForwardingFilter;
import org.apache.sshd.server.forward.ForwardingFilter;
import org.apache.sshd.server.forward.TcpForwardingFilter;
import org.apache.sshd.server.forward.X11ForwardingFilter;

/**
 * Reads and interprets some useful configurations from an OpenSSH
 * configuration file.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see <a href="http://www.freebsd.org/cgi/man.cgi?query=sshd_config&sektion=5">sshd_config(5)</a>
 */
public final class SshServerConfigFileReader {
    // Some well known configuration properties names and values
    public static final String ALLOW_TCP_FORWARDING_CONFIG_PROP = "AllowTcpForwarding";
    public static final String DEFAULT_TCP_FORWARDING = "yes";

    public static final String ALLOW_AGENT_FORWARDING_CONFIG_PROP = "AllowAgentForwarding";
    public static final String DEFAULT_AGENT_FORWARDING = "yes";

    public static final String ALLOW_X11_FORWARDING_CONFIG_PROP = "X11Forwarding";
    public static final String DEFAULT_X11_FORWARDING = "no";

    public static final String BANNER_CONFIG_PROP = "Banner";

    public static final String VISUAL_HOST_KEY = "VisualHostKey";
    public static final String DEFAULT_VISUAL_HOST_KEY = "no";

    private SshServerConfigFileReader() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    public static <S extends SshServer> S configure(
            S server, PropertyResolver props, boolean lenient, boolean ignoreUnsupported) {
        SshConfigFileReader.configure((AbstractFactoryManager) server, props, lenient, ignoreUnsupported);
        SshConfigFileReader.configureKeyExchanges(server, props, lenient, ServerBuilder.DH2KEX, ignoreUnsupported);
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
        String value = PropertyResolverUtils.getStringProperty(options,
            ALLOW_AGENT_FORWARDING_CONFIG_PROP, DEFAULT_AGENT_FORWARDING);
        return AgentForwardingFilter.of(ConfigFileReaderSupport.parseBooleanValue(value));
    }

    public static TcpForwardingFilter resolveTcpForwardingFilter(PropertyResolver options) {
        String value = PropertyResolverUtils.getStringProperty(options,
            ALLOW_TCP_FORWARDING_CONFIG_PROP, DEFAULT_TCP_FORWARDING);
        TcpForwardingFilter filter = AllowTcpForwardingValue.fromString(value);
        ValidateUtils.checkNotNull(filter, "Unknown %s value: %s", ALLOW_TCP_FORWARDING_CONFIG_PROP, value);
        return filter;
    }

    public static X11ForwardingFilter resolveX11ForwardingFilter(PropertyResolver options) {
        String value = PropertyResolverUtils.getStringProperty(options,
            ALLOW_X11_FORWARDING_CONFIG_PROP, DEFAULT_X11_FORWARDING);
        return X11ForwardingFilter.of(ConfigFileReaderSupport.parseBooleanValue(value));
    }

    public static Object resolveBanner(PropertyResolver options) {
        String bannerOption = PropertyResolverUtils.getString(options, BANNER_CONFIG_PROP);
        if (GenericUtils.isEmpty(bannerOption)) {
            bannerOption = PropertyResolverUtils.getStringProperty(options,
                VISUAL_HOST_KEY, DEFAULT_VISUAL_HOST_KEY);
            if (ConfigFileReaderSupport.parseBooleanValue(bannerOption)) {
                bannerOption = ServerAuthenticationManager.AUTO_WELCOME_BANNER_VALUE;
            } else {
                bannerOption = null;
            }
        }

        if (GenericUtils.isEmpty(bannerOption)) {
            return "Welcome to SSHD\n";
        } else if ("none".equals(bannerOption)) {
            return null;
        } else if (ServerAuthenticationManager.AUTO_WELCOME_BANNER_VALUE.equalsIgnoreCase(bannerOption)) {
            return bannerOption;
        } else {
            return Paths.get(bannerOption);
        }
    }
}
