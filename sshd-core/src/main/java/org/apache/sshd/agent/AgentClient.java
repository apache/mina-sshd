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

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.Buffer;
import org.apache.tomcat.jni.Local;
import org.apache.tomcat.jni.Pool;
import org.apache.tomcat.jni.Socket;
import org.apache.tomcat.jni.Status;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ArrayBlockingQueue;

/**
 * A client for a remote SSH agent
 */
public class AgentClient extends Thread implements SshAgent {

    private final String authSocket;
    private final long pool;
    private final long handle;
    private final Buffer receiveBuffer;
    private final Queue<Buffer> messages;
    private boolean closed;

    public AgentClient(String authSocket) throws IOException {
        try {
            this.authSocket = authSocket;
            pool = Pool.create(AprLibrary.getInstance().getRootPool());
            handle = Local.create(authSocket, pool);
            int result = Local.connect(handle, 0);
            if (result != Status.APR_SUCCESS) {
                throwException(result);
            }
            receiveBuffer = new Buffer();
            messages = new ArrayBlockingQueue<Buffer>(10);
            start();
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new SshException(e);
        }
    }

    public void run() {
        try {
            byte[] buf = new byte[1024];
            while (!closed) {
                int result = Socket.recv(handle, buf, 0, buf.length);
                if (result < Status.APR_SUCCESS) {
                    throwException(result);
                }
                messageReceived(new Buffer(buf, 0, result));
            }
        } catch (Exception e) {
            if (!closed) {
                e.printStackTrace();
            }
        } finally {
            close();
        }
    }

    protected void messageReceived(Buffer buffer) throws Exception {
        Buffer message = null;
        synchronized (receiveBuffer) {
            receiveBuffer.putBuffer(buffer);
            if (receiveBuffer.available() >= 4) {
                int rpos = receiveBuffer.rpos();
                int len = receiveBuffer.getInt();
                receiveBuffer.rpos(rpos);
                if (receiveBuffer.available() >= 4 + len) {
                    message = new Buffer(receiveBuffer.getBytes());
                    receiveBuffer.compact();
                }
            }
        }
        if (message != null) {
            synchronized (messages) {
                messages.offer(message);
                messages.notifyAll();
            }
        }
    }

    public List<Pair<PublicKey, String>> getIdentities() throws IOException {
        Buffer buffer = createBuffer(AgentServer.SSH2_AGENTC_REQUEST_IDENTITIES);
        buffer = request(buffer);
        int type = buffer.getByte();
        if (type != AgentServer.SSH2_AGENT_IDENTITIES_ANSWER) {
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
        Buffer buffer = createBuffer(AgentServer.SSH2_AGENTC_SIGN_REQUEST);
        buffer.putPublicKey(key);
        buffer.putBytes(data);
        buffer.putInt(0);
        buffer = request(buffer);
        if (buffer.getByte() != AgentServer.SSH2_AGENT_SIGN_RESPONSE) {
            throw new SshException("SSH agent failure");
        }
        Buffer buf = new Buffer(buffer.getBytes());
        buf.getString(); // algo
        return buf.getBytes();
    }

    public void addIdentity(KeyPair key, String comment) throws IOException {
        Buffer buffer = createBuffer(AgentServer.SSH2_AGENTC_ADD_IDENTITY);
        buffer.putKeyPair(key);
        buffer.putString(comment);
        buffer = request(buffer);
        if (buffer.available() != 1 || buffer.getByte() != AgentServer.SSH_AGENT_SUCCESS) {
            throw new SshException("SSH agent failure");
        }
    }

    public void removeIdentity(PublicKey key) throws IOException {
        Buffer buffer = createBuffer(AgentServer.SSH2_AGENTC_REMOVE_IDENTITY);
        buffer.putPublicKey(key);
        buffer = request(buffer);
        if (buffer.available() != 1 || buffer.getByte() != AgentServer.SSH_AGENT_SUCCESS) {
            throw new SshException("SSH agent failure");
        }
    }

    public void removeAllIdentities() throws IOException {
        Buffer buffer = createBuffer(AgentServer.SSH2_AGENTC_REMOVE_ALL_IDENTITIES);
        buffer = request(buffer);
        if (buffer.available() != 1 || buffer.getByte() != AgentServer.SSH_AGENT_SUCCESS) {
            throw new SshException("SSH agent failure");
        }
    }

    public void close() {
        if (!closed) {
            closed = true;
            Socket.close(handle);
        }
    }

    protected Buffer createBuffer(byte cmd) {
        Buffer buffer = new Buffer();
        buffer.putInt(0);
        buffer.putByte(cmd);
        return buffer;
    }

    protected synchronized Buffer request(Buffer buffer) throws IOException {
        int wpos = buffer.wpos();
        buffer.wpos(0);
        buffer.putInt(wpos - 4);
        buffer.wpos(wpos);
        synchronized (messages) {
            try {
                int result = Socket.send(handle, buffer.array(), buffer.rpos(), buffer.available());
                if (result < Status.APR_SUCCESS) {
                    throwException(result);
                }
                if (messages.isEmpty()) {
                    messages.wait();
                }
                return messages.poll();
            } catch (InterruptedException e) {
                throw (IOException) new InterruptedIOException().initCause(e);
            }
        }
    }

    /**
     * transform an APR error number in a more fancy exception
     * @param code APR error code
     * @throws java.io.IOException the produced exception for the given APR error number
     */
    private void throwException(int code) throws IOException {
        throw new IOException(
                org.apache.tomcat.jni.Error.strerror(-code) +
                " (code: " + code + ")");
    }

}
