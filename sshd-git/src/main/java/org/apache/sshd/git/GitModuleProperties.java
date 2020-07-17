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
package org.apache.sshd.git;

import java.time.Duration;

import org.apache.sshd.common.Property;

/**
 * Configurable properties for sshd-git.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class GitModuleProperties {

    /**
     * Property used to configure the SSHD {@link org.apache.sshd.common.FactoryManager} with the default timeout
     * (millis) to connect to the remote SSH server.
     */
    public static final Property<Duration> CONNECT_TIMEOUT
            = Property.duration("git-ssh-connect-timeout", Duration.ofSeconds(30L));

    /**
     * Property used to configure the SSHD {@link org.apache.sshd.common.FactoryManager} with the default timeout
     * (millis) to authenticate with the remote SSH server.
     */
    public static final Property<Duration> AUTH_TIMEOUT
            = Property.duration("git-ssh-connect-timeout", Duration.ofSeconds(15L));

    /**
     * Property used to configure the SSHD {@link org.apache.sshd.common.FactoryManager} with the default timeout
     * (millis) to open a channel to the remote SSH server. is used.
     */
    public static final Property<Duration> CHANNEL_OPEN_TIMEOUT
            = Property.duration("git-ssh-channel-open-timeout", Duration.ofSeconds(7L));

    private GitModuleProperties() {
        // private
    }

}
