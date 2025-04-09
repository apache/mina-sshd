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
package org.apache.sshd.client.config;

import java.time.Duration;
import java.util.Map;

import org.apache.sshd.client.ClientBuilder;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.common.CommonModuleProperties;
import org.apache.sshd.common.Property;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.config.SshConfigFileReader;
import org.apache.sshd.common.session.SessionHeartbeatController.HeartbeatType;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class SshClientConfigFileReader {
    public static final String SETENV_PROP = "SetEnv";
    public static final String SENDENV_PROP = "SendEnv";
    public static final String REQUEST_TTY_OPTION = "RequestTTY";

    public static final Property<Duration> CLIENT_LIVECHECK_INTERVAL_PROP
            = Property.duration("ServerAliveInterval", Duration.ZERO);

    public static final Property<Boolean> CLIENT_LIVECHECK_USE_NULLS = Property.bool("ServerAliveUseNullPackets", false);

    public static final int DEFAULT_LIVECHECK_MISSED_REPLIES_MAX = 3;
    public static final Property<Integer> CLIENT_LIVECHECK_MISSED_REPLIES_MAX = Property.integer("ServerAliveCountMax",
            DEFAULT_LIVECHECK_MISSED_REPLIES_MAX);

    private SshClientConfigFileReader() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    public static <C extends SshClient> C setupClientHeartbeat(C client, PropertyResolver props) {
        if ((client == null) || (props == null)) {
            return client;
        }

        Duration interval = CLIENT_LIVECHECK_INTERVAL_PROP.getRequired(props);
        if (GenericUtils.isNegativeOrNull(interval)) {
            return client;
        }

        if (CLIENT_LIVECHECK_USE_NULLS.getRequired(props).booleanValue()) {
            CommonModuleProperties.SESSION_HEARTBEAT_TYPE.set(client, HeartbeatType.IGNORE);
            CommonModuleProperties.SESSION_HEARTBEAT_INTERVAL.set(client, interval);
        } else {
            CoreModuleProperties.HEARTBEAT_INTERVAL.set(client, interval);

            int n = CLIENT_LIVECHECK_MISSED_REPLIES_MAX.getRequired(props);
            if (!GenericUtils.isNegativeOrNull(interval)) {
                CoreModuleProperties.HEARTBEAT_NO_REPLY_MAX.set(client, n);
            }
        }

        return client;
    }

    public static <C extends SshClient> C setupClientHeartbeat(C client, Map<String, ?> options) {
        if ((client == null) || MapEntryUtils.isEmpty(options)) {
            return client;
        }

        return setupClientHeartbeat(client, PropertyResolverUtils.toPropertyResolver(options));
    }

    public static <C extends SshClient> C configure(
            C client, PropertyResolver props, boolean lenient, boolean ignoreUnsupported) {
        SshConfigFileReader.configure(client, props, lenient, ignoreUnsupported);
        SshConfigFileReader.configureKeyExchanges(client, props, lenient, ClientBuilder.DH2KEX, ignoreUnsupported);
        setupClientHeartbeat(client, props);
        return client;
    }
}
