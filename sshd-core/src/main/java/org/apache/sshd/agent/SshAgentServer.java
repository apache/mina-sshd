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
package org.apache.sshd.agent;

import java.nio.channels.Channel;
import java.util.concurrent.TimeUnit;

public interface SshAgentServer extends Channel {

    /**
     * Value that can be set on the {@link org.apache.sshd.common.FactoryManager} or the session to configure the
     * channel open timeout value (millis). If not specified then {@link #DEFAULT_CHANNEL_OPEN_TIMEOUT} value is used
     */
    String CHANNEL_OPEN_TIMEOUT_PROP = "ssh-agent-server-channel-open-timeout";

    long DEFAULT_CHANNEL_OPEN_TIMEOUT = TimeUnit.SECONDS.toMillis(30L);

    /**
     * Value used to configure the type of proxy forwarding channel to be used. If not specified, then
     * {@link #DEFAULT_PROXY_CHANNEL_TYPE} is used
     */
    String PROXY_CHANNEL_TYPE = "ssh-agent-server-channel-proxy-type";
    // see also https://tools.ietf.org/html/draft-ietf-secsh-agent-02
    String DEFAULT_PROXY_CHANNEL_TYPE = "auth-agent@openssh.com";

    /**
     * @return Agent server identifier
     */
    String getId();

}
