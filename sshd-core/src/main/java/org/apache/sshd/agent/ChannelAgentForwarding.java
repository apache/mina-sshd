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

import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Channel;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.channel.AbstractServerChannel;
import org.apache.tomcat.jni.Local;
import org.apache.tomcat.jni.Pool;
import org.apache.tomcat.jni.Socket;
import org.apache.tomcat.jni.Status;

import java.io.IOException;
import java.io.OutputStream;

/**
 * The client side channel that will receive requests forwards by the SSH server.
 */
public class ChannelAgentForwarding extends AbstractServerChannel {

    public static class Factory implements NamedFactory<Channel> {

        public String getName() {
            return "auth-agent@openssh.com";
        }

        public Channel create() {
            return new ChannelAgentForwarding();
        }
    }

    private String authSocket;
    private long pool;
    private long handle;
    private Thread thread;
    private OutputStream out;

    public ChannelAgentForwarding() {
    }

    protected OpenFuture doInit(Buffer buffer) {
        final OpenFuture f = new DefaultOpenFuture(this);
        try {
            out = new ChannelOutputStream(this, remoteWindow, log, SshConstants.Message.SSH_MSG_CHANNEL_DATA);
            authSocket = session.getFactoryManager().getProperties().get(SshAgent.SSH_AUTHSOCKET_ENV_NAME);
            pool = Pool.create(AprLibrary.getInstance().getRootPool());
            handle = Local.create(authSocket, pool);
            int result = Local.connect(handle, 0);
            if (result != Status.APR_SUCCESS) {
                throwException(result);
            }
            thread = new Thread() {
                public void run() {
                    try {
                        byte[] buf = new byte[1024];
                        while (true) {
                            int len = Socket.recv(handle, buf, 0, buf.length);
                            if (len > 0) {
                                out.write(buf, 0, len);
                                out.flush();
                            }
                        }
                    } catch (IOException e) {
                        close(true);
                    }
                }
            };
            thread.start();
            f.setOpened();

        } catch (Exception e) {
            f.setException(e);
        }
        return f;
    }

    private void closeImmediately0() {
        // We need to close the channel immediately to remove it from the
        // server session's channel table and *not* send a packet to the
        // client.  A notification was already sent by our caller, or will
        // be sent after we return.
        //
        super.close(true);

        // We also need to close the socket.
        //
        Socket.close(handle);
    }

    public CloseFuture close(boolean immediately) {
        return super.close(immediately).addListener(new SshFutureListener() {
            public void operationComplete(SshFuture sshFuture) {
                closeImmediately0();
            }
        });
    }

    @Override
    public void handleEof() throws IOException {
        super.handleEof();
//        close(true);
    }

    protected void doWriteData(byte[] data, int off, int len) throws IOException {
        int result = Socket.send(handle, data, off, len);
        if (result < Status.APR_SUCCESS) {
            throwException(result);
        }
    }

    protected void doWriteExtendedData(byte[] data, int off, int len) throws IOException {
        throw new UnsupportedOperationException("AgentForward channel does not support extended data");
    }

    public void handleRequest(Buffer buffer) throws IOException {
        log.info("Received SSH_MSG_CHANNEL_REQUEST on channel {}", id);
        String type = buffer.getString();
        log.info("Received channel request: {}", type);
        buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_FAILURE, 0);
        buffer.putInt(recipient);
        session.writePacket(buffer);
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
