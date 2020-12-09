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

package org.apache.sshd.cli.client;

import java.time.Duration;

import org.apache.sshd.common.Property;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class CliClientModuleProperties {
    /**
     * Key used to retrieve the value of the timeout after which it will abort the connection if the connection has not
     * been established - in milliseconds.
     */
    public static final Property<Duration> CONECT_TIMEOUT
            = Property.duration("cli-connect-timeout", Duration.ofMinutes(2));

    /**
     * Key used to retrieve the value of the timeout after which it will close the connection if the other side has not
     * been authenticated - in milliseconds.
     */
    public static final Property<Duration> AUTH_TIMEOUT
            = Property.duration("cli-auth-timeout", Duration.ofMinutes(2));

    /**
     * Key used to retrieve the value of the timeout for opening an EXEC or SHELL channel - in msec.
     */
    public static final Property<Duration> CHANNEL_OPEN_TIMEOUT
            = Property.duration("cli-channel-open-timeout", Duration.ofSeconds(30));

    private CliClientModuleProperties() {
        throw new UnsupportedOperationException("No instance");
    }
}
