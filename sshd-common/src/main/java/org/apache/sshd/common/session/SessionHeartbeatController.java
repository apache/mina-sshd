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

package org.apache.sshd.common.session;

import java.time.Duration;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.CommonModuleProperties;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SessionHeartbeatController extends PropertyResolver {
    enum HeartbeatType {
        /** No heartbeat */
        NONE,
        /** Use {@code SSH_MSG_IGNORE} packets */
        IGNORE,
        /** Custom mechanism via {@code ReservedSessionMessagesHandler} */
        RESERVED;

        public static final Set<HeartbeatType> VALUES = EnumSet.allOf(HeartbeatType.class);

        public static HeartbeatType fromName(String name) {
            return GenericUtils.isEmpty(name)
                    ? null
                    : VALUES.stream()
                            .filter(v -> name.equalsIgnoreCase(v.name()))
                            .findAny()
                            .orElse(null);
        }
    }

    default HeartbeatType getSessionHeartbeatType() {
        return CommonModuleProperties.SESSION_HEARTBEAT_TYPE.getRequired(this);
    }

    default Duration getSessionHeartbeatInterval() {
        return CommonModuleProperties.SESSION_HEARTBEAT_INTERVAL.getRequired(this);
    }

    /**
     * Disables the session heartbeat feature - <B>Note:</B> if heartbeat already in progress then it may be ignored.
     */
    default void disableSessionHeartbeat() {
        setSessionHeartbeat(HeartbeatType.NONE, Duration.ZERO);
    }

    default void setSessionHeartbeat(HeartbeatType type, TimeUnit unit, long count) {
        Objects.requireNonNull(unit, "No heartbeat time unit provided");
        setSessionHeartbeat(type, Duration.ofMillis(TimeUnit.MILLISECONDS.convert(count, unit)));
    }

    /**
     * Set the session heartbeat
     *
     * @param type     The type of {@link HeartbeatType heartbeat} to use
     * @param interval The (never {@code null}) heartbeat interval - its milliseconds value is used
     */
    default void setSessionHeartbeat(HeartbeatType type, Duration interval) {
        Objects.requireNonNull(type, "No heartbeat type specified");
        Objects.requireNonNull(interval, "No heartbeat time interval provided");
        CommonModuleProperties.SESSION_HEARTBEAT_TYPE.set(this, type);
        CommonModuleProperties.SESSION_HEARTBEAT_INTERVAL.set(this, interval);
    }
}
