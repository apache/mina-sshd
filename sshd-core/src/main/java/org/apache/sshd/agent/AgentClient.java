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

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.service.IoConnector;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.nio.NioSocketConnector;
import org.apache.sshd.SshAgent;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.Buffer;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ArrayBlockingQueue;

/**
 * A client for a remote SSH agent
 */
public class AgentClient implements SshAgent {

    private IoConnector connector;
    private SocketAddress address;
    private ConnectFuture connect;
    private IoSession session;
    private Buffer receiveBuffer;
    private final Queue<Buffer> messages;

    public AgentClient(String authSocket) {
        connector = new NioSocketConnector();
        connector.setHandler(new IoHandlerAdapter() {
            @Override
            public void messageReceived(IoSession session, Object message) throws Exception {
                IoBuffer ioBuffer = (IoBuffer) message;
                AgentClient.this.messageReceived(ioBuffer);
            }
//                @Override
//                public void sessionClosed(IoSession session) throws Exception {
//                    close();
//                }
        });
        address = new InetSocketAddress("localhost", Integer.parseInt(authSocket));
        receiveBuffer = new Buffer();
        messages = new ArrayBlockingQueue<Buffer>(10);
        connect = connector.connect(address);
    }

    protected IoSession getSession() throws Throwable {
        if (session == null) {
            connect.await();
            if (connect.getException() != null) {
                throw connect.getException();
            }
            session = connect.getSession();
        }
        return session;
    }

    protected void messageReceived(IoBuffer buffer) throws Exception {
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
        if (session != null) {
            session.close(true);
        }
        connector.dispose();
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
                IoBuffer buf = IoBuffer.allocate(buffer.available());
                buf.put(buffer.array(), buffer.rpos(), buffer.available());
                buf.flip();
                connect.await().getSession().write(buf);
                if (messages.isEmpty()) {
                    messages.wait();
                }
                return messages.poll();
            } catch (InterruptedException e) {
                throw (IOException) new InterruptedIOException().initCause(e);
            }
        }
    }

}
