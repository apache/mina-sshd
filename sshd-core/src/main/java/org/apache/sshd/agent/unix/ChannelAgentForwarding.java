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
package org.apache.sshd.agent.unix;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Collection;
import java.util.Collections;
import java.util.concurrent.Future;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.channel.AbstractServerChannel;
import org.apache.tomcat.jni.Local;
import org.apache.tomcat.jni.Pool;
import org.apache.tomcat.jni.Socket;
import org.apache.tomcat.jni.Status;

/**
 * The client side channel that will receive requests forwards by the SSH server.
 */
public class ChannelAgentForwarding extends AbstractServerChannel {

    private String authSocket;
    private long pool;
    private long handle;
    private OutputStream out;
    private CloseableExecutorService forwardService;
    private Future<?> forwarder;

    public ChannelAgentForwarding(CloseableExecutorService executor) {
        super("", Collections.emptyList(), executor);
    }

    @Override
    protected OpenFuture doInit(Buffer buffer) {
        OpenFuture f = new DefaultOpenFuture(this, this);
        try {
            out = new ChannelOutputStream(this, getRemoteWindow(), log, SshConstants.SSH_MSG_CHANNEL_DATA, true);
            authSocket = this.getString(SshAgent.SSH_AUTHSOCKET_ENV_NAME);
            pool = Pool.create(AprLibrary.getInstance().getRootPool());
            handle = Local.create(authSocket, pool);
            int result = Local.connect(handle, 0);
            if (result != Status.APR_SUCCESS) {
                throwException(result);
            }

            CloseableExecutorService service = getExecutorService();
            forwardService = (service == null)
                    ? ThreadUtils.newSingleThreadExecutor("ChannelAgentForwarding[" + authSocket + "]")
                    : ThreadUtils.noClose(service);

            int copyBufSize = CoreModuleProperties.FORWARDER_BUFFER_SIZE.getRequired(this);
            ValidateUtils.checkTrue(copyBufSize >= CoreModuleProperties.MIN_FORWARDER_BUF_SIZE,
                    "Copy buf size below min.: %d", copyBufSize);
            ValidateUtils.checkTrue(copyBufSize <= CoreModuleProperties.MAX_FORWARDER_BUF_SIZE,
                    "Copy buf size above max.: %d", copyBufSize);

            forwarder = forwardService.submit(() -> {
                try {
                    byte[] buf = new byte[copyBufSize];
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
            });

            signalChannelOpenSuccess();
            f.setOpened();
        } catch (Throwable t) {
            Throwable e = GenericUtils.peelException(t);
            signalChannelOpenFailure(e);
            f.setException(e);
        }

        return f;
    }

    private void closeImmediately0() {
        // We need to close the channel immediately to remove it from the
        // server session's channel table and *not* send a packet to the
        // client. A notification was already sent by our caller, or will
        // be sent after we return.
        //
        super.close(true);

        // We also need to close the socket.
        Socket.close(handle);

        try {
            if ((forwarder != null) && (!forwarder.isDone())) {
                forwarder.cancel(true);
            }
        } finally {
            forwarder = null;
        }

        try {
            if (forwardService != null) {
                Collection<?> runners = forwardService.shutdownNow();
                if (log.isDebugEnabled()) {
                    log.debug("Shut down runners count=" + GenericUtils.size(runners));
                }
            }
        } finally {
            forwardService = null;
        }
    }

    @Override
    protected Closeable getInnerCloseable() {
        return builder()
                .close(super.getInnerCloseable())
                .run(toString(), this::closeImmediately0)
                .build();
    }

    @Override
    protected void doWriteData(byte[] data, int off, long len) throws IOException {
        ValidateUtils.checkTrue(len <= Integer.MAX_VALUE,
                "Data length exceeds int boundaries: %d", len);
        int result = Socket.send(handle, data, off, (int) len);
        if (result < Status.APR_SUCCESS) {
            throwException(result);
        }
    }

    @Override
    protected void doWriteExtendedData(byte[] data, int off, long len) throws IOException {
        throw new UnsupportedOperationException(
                "AgentForward channel does not support extended data");
    }

    /**
     * transform an APR error number in a more fancy exception
     *
     * @param  code                APR error code
     * @throws java.io.IOException the produced exception for the given APR error number
     */
    private static void throwException(int code) throws IOException {
        throw new IOException(org.apache.tomcat.jni.Error.strerror(-code) + " (code: " + code + ")");
    }
}
