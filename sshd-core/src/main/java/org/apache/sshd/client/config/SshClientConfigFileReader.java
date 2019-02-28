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

import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.ClientBuilder;
import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.config.SshConfigFileReader;
import org.apache.sshd.common.helpers.AbstractFactoryManager;
import org.apache.sshd.common.session.SessionHeartbeatController.HeartbeatType;
import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class SshClientConfigFileReader {
    public static final String SETENV_PROP = "SetEnv";
    public static final String SENDENV_PROP = "SendEnv";
    public static final String REQUEST_TTY_OPTION = "RequestTTY";

    public static final String CLIENT_LIVECHECK_INTERVAL_PROP = "ClientAliveInterval";
    public static final long DEFAULT_ALIVE_INTERVAL = 0L;

    public static final String CLIENT_LIVECHECK_USE_NULLS = "ClientAliveUseNullPackets";
    public static final boolean DEFAULT_LIVECHECK_USE_NULLS = false;

    public static final String CLIENT_LIVECHECK_REPLIES_WAIT = "ClientAliveReplyWait";
    public static final long DEFAULT_LIVECHECK_REPLY_WAIT = 0L;

    private SshClientConfigFileReader() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    public static <C extends SshClient> C setupClientHeartbeat(C client, PropertyResolver props) {
        if ((client == null) || (props == null)) {
            return client;
        }

        long interval = PropertyResolverUtils.getLongProperty(
                props, CLIENT_LIVECHECK_INTERVAL_PROP, DEFAULT_ALIVE_INTERVAL);
        if (interval <= 0L) {
            return client;
        }

        if (PropertyResolverUtils.getBooleanProperty(
                props, CLIENT_LIVECHECK_USE_NULLS, DEFAULT_LIVECHECK_USE_NULLS)) {
            client.setSessionHeartbeat(HeartbeatType.IGNORE, TimeUnit.SECONDS, interval);
        } else {
            PropertyResolverUtils.updateProperty(
                client, ClientFactoryManager.HEARTBEAT_INTERVAL, TimeUnit.SECONDS.toMillis(interval));

            interval = PropertyResolverUtils.getLongProperty(
                props, CLIENT_LIVECHECK_REPLIES_WAIT, DEFAULT_LIVECHECK_REPLY_WAIT);
            if (interval > 0L) {
                PropertyResolverUtils.updateProperty(
                    client, ClientFactoryManager.HEARTBEAT_REPLY_WAIT, TimeUnit.SECONDS.toMillis(interval));
            }
        }

        return client;
    }

    public static <C extends SshClient> C setupClientHeartbeat(C client, Map<String, ?> options) {
        if ((client == null) || GenericUtils.isEmpty(options)) {
            return client;
        }

        return setupClientHeartbeat(client, PropertyResolverUtils.toPropertyResolver(options));
    }

    public static <C extends SshClient> C configure(
            C client, PropertyResolver props, boolean lenient, boolean ignoreUnsupported) {
        SshConfigFileReader.configure((AbstractFactoryManager) client, props, lenient, ignoreUnsupported);
        SshConfigFileReader.configureKeyExchanges(client, props, lenient, ClientBuilder.DH2KEX, ignoreUnsupported);
        setupClientHeartbeat(client, props);
        return client;
    }
}
