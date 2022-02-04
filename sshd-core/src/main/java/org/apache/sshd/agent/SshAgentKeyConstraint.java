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

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * A {@link SshAgentKeyConstraint} describes usage constraints for keys when being added to an SSH2 agent.
 */
public abstract class SshAgentKeyConstraint {

    /**
     * The singleton OpenSSH confirmation {@link SshAgentKeyConstraint}. If set, the SSH agent is supposed to prompt the
     * user before each use of a key in a signing operation.
     * <p>
     * Users who have this option set via ssh config {@code AddKeysToAgent confirm} are responsible themselves for
     * having configured their agent correctly so that it prompts in whatever way is appropriate.
     * </p>
     * <p>
     * The OpenSSH agent prompts via via {@code ssh-askpass} or whatever program the environment variable SSH_ASKPASS
     * defines. These prompts don't go through the prompting callback mechanisms of Apache MINA sshd.
     * </p>
     */
    public static final SshAgentKeyConstraint CONFIRM = new SshAgentKeyConstraint(
            SshAgentConstants.SSH_AGENT_CONSTRAIN_CONFIRM) {
        // Nothing
    };

    private final byte id;

    /**
     * Constructor setting the agent protocol ID of the constraint.
     *
     * @param id for the key constraint
     */
    protected SshAgentKeyConstraint(byte id) {
        this.id = id;
    }

    /**
     * Retrieves the protocol ID of this constraint.
     *
     * @return the protocol id of this constraint
     */
    public byte getId() {
        return id;
    }

    /**
     * Writes this constraint into the given {@link Buffer}.
     *
     * @param buffer {@link Buffer} to write into at the current buffer write position
     */
    public void put(Buffer buffer) {
        buffer.putByte(id);
    }

    /**
     * An OpenSSH lifetime constraint expires a key added to an SSH agent after the given number of seconds.
     */
    public static class LifeTime extends SshAgentKeyConstraint {

        private final int secondsToLive;

        /**
         * Creates a new {@link LifeTime} constraint.
         *
         * @param secondsToLive number of seconds after which the agent shall automatically remove the key again; must
         *                      be strictly positive
         */
        public LifeTime(int secondsToLive) {
            super(SshAgentConstants.SSH_AGENT_CONSTRAIN_LIFETIME);
            if (secondsToLive <= 0) {
                throw new IllegalArgumentException("Key lifetime must be > 0, was " + secondsToLive);
            }
            this.secondsToLive = secondsToLive;
        }

        @Override
        public void put(Buffer buffer) {
            super.put(buffer);
            buffer.putUInt(secondsToLive);
        }
    }

    /**
     * An OpenSSH {@link SshAgentKeyConstraint} extension. Extensions are identified by name.
     */
    public abstract static class Extension extends SshAgentKeyConstraint {

        private final String name;

        /**
         * Creates a new {@link Extension}.
         *
         * @param name of the extension, must not be {@code null} or empty
         */
        protected Extension(String name) {
            super(SshAgentConstants.SSH_AGENT_CONSTRAIN_EXTENSION);
            if (GenericUtils.isEmpty(name)) {
                throw new IllegalArgumentException("Key constraint extension name must be non-empty");
            }
            this.name = name;
        }

        @Override
        public void put(Buffer buffer) {
            super.put(buffer);
            buffer.putString(name);
        }
    }

    /**
     * The OpenSSH "sk-provider@openssh.com" key constraint extension used for FIDO keys. Could be set via ssh config
     * {@code SecurityKeyProvider}.
     */
    public static class FidoProviderExtension extends Extension {

        private final String provider;

        /**
         * Creates a new {@link FidoProviderExtension}.
         *
         * @param provider path to a middleware library; must not be {@code null} or empty
         */
        public FidoProviderExtension(String provider) {
            super("sk-provider@openssh.com");
            if (GenericUtils.isEmpty(provider)) {
                throw new IllegalArgumentException("FIDO provider library path must be non-empty");
            }
            this.provider = provider;
        }

        @Override
        public void put(Buffer buffer) {
            super.put(buffer);
            buffer.putString(provider);
        }
    }
}
