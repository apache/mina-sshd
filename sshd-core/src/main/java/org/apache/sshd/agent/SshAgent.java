/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.agent;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;

/**
 * SSH key agent server
 */
public interface SshAgent {

    public static final String SSH_AUTHSOCKET_ENV_NAME = "SSH_AUTH_SOCK";

    public static class Pair<U,V> {
        private final U first;
        private final V second;

        public Pair(U first, V second) {
            this.first = first;
            this.second = second;
        }

        public U getFirst() {
            return first;
        }

        public V getSecond() {
            return second;
        }
    }

    List<Pair<PublicKey, String>> getIdentities() throws IOException;

    byte[] sign(PublicKey key, byte[] data) throws IOException;

    void addIdentity(KeyPair key, String comment) throws IOException;

    void removeIdentity(PublicKey key) throws IOException;

    void removeAllIdentities() throws IOException;

    void close();

}
