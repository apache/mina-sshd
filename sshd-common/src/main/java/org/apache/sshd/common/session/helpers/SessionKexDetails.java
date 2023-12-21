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

import java.time.Instant;

import org.apache.sshd.common.kex.KexState;

/**
 * Provides some useful internal information about the session's KEX
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SessionKexDetails {
    private KexState kexState;
    private boolean initialKexDone;
    private boolean strictKexEnabled;
    private boolean strictKexSignalled;
    private int newKeysSentCount;
    private int newKeysReceivedCount;
    private Instant lastKeyTimeValue;

    public SessionKexDetails() {
        super();
    }

    public KexState getKexState() {
        return kexState;
    }

    public void setKexState(KexState kexState) {
        this.kexState = kexState;
    }

    public boolean isInitialKexDone() {
        return initialKexDone;
    }

    public void setInitialKexDone(boolean initialKexDone) {
        this.initialKexDone = initialKexDone;
    }

    public boolean isStrictKexEnabled() {
        return strictKexEnabled;
    }

    public void setStrictKexEnabled(boolean strictKexEnabled) {
        this.strictKexEnabled = strictKexEnabled;
    }

    public boolean isStrictKexSignalled() {
        return strictKexSignalled;
    }

    public void setStrictKexSignalled(boolean strictKexSignalled) {
        this.strictKexSignalled = strictKexSignalled;
    }

    // TODO add the KEX extensions values (if any)

    /**
     * @return Number of times the session sent the {@code SSH_MSG_NEWKEYS} command
     */
    public int getNewKeysSentCount() {
        return newKeysSentCount;
    }

    public void setNewKeysSentCount(int newKeysSentCount) {
        this.newKeysSentCount = newKeysSentCount;
    }

    /**
     * @return Number of times the session received the {@code SSH_MSG_NEWKEYS} command
     */
    public int getNewKeysReceivedCount() {
        return newKeysReceivedCount;
    }

    public void setNewKeysReceivedCount(int newKeysReceivedCount) {
        this.newKeysReceivedCount = newKeysReceivedCount;
    }

    /**
     * @return Last {@link Instant} when new keys were established - may be {@code null} if new keys not yet established
     */
    public Instant getLastKeyTimeValue() {
        return lastKeyTimeValue;
    }

    public void setLastKeyTimeValue(Instant lastKeyTimeValue) {
        this.lastKeyTimeValue = lastKeyTimeValue;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[initialKexDone=" + isInitialKexDone()
               + ", kexState=" + getKexState()
               + ", strictKexEnabled=" + isStrictKexEnabled()
               + ", strictKexSignalled=" + isStrictKexSignalled()
               + ", newKeysSentCount=" + getNewKeysSentCount()
               + ", newKeysReceivedCount=" + getNewKeysReceivedCount()
               + ", lastKeyTimeValue=" + getLastKeyTimeValue()
               + "]";
    }
}
