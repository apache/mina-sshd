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
package org.apache.sshd.agent.common;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.Buffer;

import static org.apache.sshd.agent.SshAgentConstants.*;

public abstract class AbstractAgentProxy implements SshAgent {

    public List<Pair<PublicKey, String>> getIdentities() throws IOException {
        Buffer buffer = createBuffer(SSH2_AGENTC_REQUEST_IDENTITIES);
        buffer = request(prepare(buffer));
        int type = buffer.getByte();
        if (type != SSH2_AGENT_IDENTITIES_ANSWER) {
            throw new SshException("SSH agent failure");
        }
        int nbIdentities = buffer.getInt();
        if (nbIdentities > 1024) {
            throw new SshException("SSH agent failure");
        }
        List<Pair<PublicKey, String>> keys = new ArrayList<Pair<PublicKey, String>>();
        for (int i = 0; i < nbIdentities; i++) {
            PublicKey key = buffer.getPublicKey();
            keys.add(new Pair<PublicKey, String>(key, buffer.getString()));
        }
        return keys;
    }

    public byte[] sign(PublicKey key, byte[] data) throws IOException {
        Buffer buffer = createBuffer(SSH2_AGENTC_SIGN_REQUEST);
        buffer.putPublicKey(key);
        buffer.putBytes(data);
        buffer.putInt(0);
        buffer = request(prepare(buffer));
        if (buffer.getByte() != SSH2_AGENT_SIGN_RESPONSE) {
            throw new SshException("SSH agent failure");
        }
        Buffer buf = new Buffer(buffer.getBytes());
        buf.getString(); // algo
        return buf.getBytes();
    }

    public void addIdentity(KeyPair key, String comment) throws IOException {
        Buffer buffer = createBuffer(SSH2_AGENTC_ADD_IDENTITY);
        buffer.putKeyPair(key);
        buffer.putString(comment);
        buffer = request(prepare(buffer));
        if (buffer.available() != 1 || buffer.getByte() != SSH_AGENT_SUCCESS) {
            throw new SshException("SSH agent failure");
        }
    }

    public void removeIdentity(PublicKey key) throws IOException {
        Buffer buffer = createBuffer(SSH2_AGENTC_REMOVE_IDENTITY);
        buffer.putPublicKey(key);
        buffer = request(prepare(buffer));
        if (buffer.available() != 1 || buffer.getByte() != SSH_AGENT_SUCCESS) {
            throw new SshException("SSH agent failure");
        }
    }

    public void removeAllIdentities() throws IOException {
        Buffer buffer = createBuffer(SSH2_AGENTC_REMOVE_ALL_IDENTITIES);
        buffer = request(prepare(buffer));
        if (buffer.available() != 1 || buffer.getByte() != SSH_AGENT_SUCCESS) {
            throw new SshException("SSH agent failure");
        }
    }

    public void close() {
    }

    protected Buffer createBuffer(byte cmd) {
        Buffer buffer = new Buffer();
        buffer.putInt(0);
        buffer.putByte(cmd);
        return buffer;
    }

    protected Buffer prepare(Buffer buffer) {
        int wpos = buffer.wpos();
        buffer.wpos(0);
        buffer.putInt(wpos - 4);
        buffer.wpos(wpos);
        return buffer;
    }

    protected abstract Buffer request(Buffer buffer) throws IOException;

}
