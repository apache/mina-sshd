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
package org.apache.sshd.client.channel;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * Various events used by {@link ClientChannel#waitFor(java.util.Collection, long)}
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum ClientChannelEvent {
    /**
     * Timeout while waiting for other events - <B>Note:</B> meaningful only as a member of the <U>returned</U> events
     **/
    TIMEOUT,
    /** Channel has been marked as closed **/
    CLOSED,
    /** Received STDOUT (a.k.a. channel) data **/
    STDOUT_DATA,
    /** Received STDERR (a.k.a. extended) data **/
    STDERR_DATA,
    /** Received EOF signal from remote peer **/
    EOF,
    /**
     * Received exit status from remote peer
     * 
     * @see ClientChannel#getExitStatus()
     **/
    EXIT_STATUS,
    /**
     * Received exit signal from remote peer
     * 
     * @see ClientChannel#getExitSignal()
     */
    EXIT_SIGNAL,
    /** Channel has been successfully opened */
    OPENED;

    public static final Set<ClientChannelEvent> VALUES = Collections.unmodifiableSet(EnumSet.allOf(ClientChannelEvent.class));
}
