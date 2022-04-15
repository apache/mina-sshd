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

package org.apache.sshd.common.kex;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * Used to track the key-exchange (KEX) protocol progression.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum KexState {
    UNKNOWN,

    /**
     * A key exchange has been initiated by this party.
     */
    INIT,

    /**
     * A key exchange is running. Both sides have received the peer's SSH_MSG_KEX_INIT.
     */
    RUN,

    /**
     * Keys have been exchanged; this party has sent its SSH_MSG_NEW_KEYS.
     */
    KEYS,

    /**
     * The key exchange is done; both parties have received the peer's SSH:MSG_NEW_KEYS, and there is no ongoing key
     * exchange.
     */
    DONE;

    public static final Set<KexState> VALUES = Collections.unmodifiableSet(EnumSet.allOf(KexState.class));
}
