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

package org.apache.sshd.common.session.helpers;

import java.time.Duration;

/**
 * Used to convey information about an expired timeout
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class TimeoutIndicator {
    /**
     * Timeout status.
     */
    public enum TimeoutStatus {
        NoTimeout,
        AuthTimeout,
        IdleTimeout
    }

    public static final TimeoutIndicator NONE = new TimeoutIndicator(TimeoutStatus.NoTimeout, Duration.ZERO, Duration.ZERO);

    private final TimeoutStatus status;
    private final Duration thresholdValue;
    private final Duration expiredValue;

    /**
     * @param status         The expired timeout type (if any)
     * @param thresholdValue The configured timeout value
     * @param expiredValue   The actual value that cause the timeout
     */
    public TimeoutIndicator(TimeoutStatus status, Duration thresholdValue, Duration expiredValue) {
        this.status = status;
        this.thresholdValue = thresholdValue;
        this.expiredValue = expiredValue;
    }

    public TimeoutStatus getStatus() {
        return status;
    }

    public Duration getThresholdValue() {
        return thresholdValue;
    }

    public Duration getExpiredValue() {
        return expiredValue;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[status=" + getStatus()
               + ", threshold=" + getThresholdValue()
               + ", expired=" + getExpiredValue()
               + "]";
    }
}
