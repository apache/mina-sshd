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
package org.apache.sshd.common;

import java.time.Duration;

import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.session.SessionHeartbeatController;

/**
 * Configurable properties for sshd-common.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class CommonModuleProperties {

    /**
     * If set to {@code true} then
     * {@link org.apache.sshd.common.auth.UserAuthMethodFactory#isSecureAuthenticationTransport(SessionContext)} returns
     * {@code true} even if transport is insecure.
     */
    public static final Property<Boolean> ALLOW_INSECURE_AUTH
            = Property.bool("allow-insecure-auth", false);

    /**
     * If set to {@code true} then
     * {@link org.apache.sshd.common.auth.UserAuthMethodFactory#isDataIntegrityAuthenticationTransport(SessionContext)}
     * returns {@code true} even if transport has no MAC(s) to verify message integrity
     */
    public static final Property<Boolean> ALLOW_NON_INTEGRITY_AUTH
            = Property.bool("allow-non-integrity-auth", false);

    /**
     * Property used to register the {@link org.apache.sshd.common.session.SessionHeartbeatController.HeartbeatType} -
     * if non-existent or {@code NONE} then disabled. Same if some unknown string value is set as the property value.
     */
    public static final Property<SessionHeartbeatController.HeartbeatType> SESSION_HEARTBEAT_TYPE
            = Property.enum_("session-connection-heartbeat-type", SessionHeartbeatController.HeartbeatType.class,
                    SessionHeartbeatController.HeartbeatType.NONE);

    /** Property used to register the interval for the heartbeat - if not set or non-positive then disabled */
    public static final Property<Duration> SESSION_HEARTBEAT_INTERVAL
            = Property.duration("session-connection-heartbeat-interval", Duration.ZERO);

    public static final Property<Integer> HEXDUMP_CHUNK_SIZE
            = Property.integer("sshd-hexdump-chunk-size", 64);

    /**
     * Timeout (milliseconds) for waiting on a {@link CloseFuture} to successfully complete its action.
     */
    public static final Property<Duration> CLOSE_WAIT_TIMEOUT
            = Property.duration("sshd-close-wait-time", Duration.ofSeconds(15L));

    private CommonModuleProperties() {
        throw new UnsupportedOperationException("No instance");
    }
}
