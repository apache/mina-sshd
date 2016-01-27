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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.ChannelListener;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.server.channel.AbstractServerChannel;
import org.apache.tomcat.jni.Local;
import org.apache.tomcat.jni.Pool;
import org.apache.tomcat.jni.Socket;
import org.apache.tomcat.jni.Status;

/**
 * The client side channel that will receive requests forwards by the SSH server.
 */
public class ChannelAgentForwarding extends AbstractServerChannel {
    /**
     * Property that can be set on the factory manager in order to control
     * the buffer size used to forward data from the established channel
     *
     * @see #MIN_FORWARDER_BUF_SIZE
     * @see #MAX_FORWARDER_BUF_SIZE
     * @see #DEFAULT_FORWARDER_BUF_SIZE
     */
    public static final String FORWARDER_BUFFER_SIZE = "channel-agent-fwd-buf-size";
    public static final int MIN_FORWARDER_BUF_SIZE = Byte.MAX_VALUE;
    public static final int DEFAULT_FORWARDER_BUF_SIZE = 1024;
    public static final int MAX_FORWARDER_BUF_SIZE = Short.MAX_VALUE;

    private String authSocket;
    private long pool;
    private long handle;
    private OutputStream out;
    private ExecutorService forwardService;
    private Future<?> forwarder;
    private boolean shutdownForwarder;

    public ChannelAgentForwarding() {
        super();
    }

    @Override
    protected OpenFuture doInit(Buffer buffer) {
        final OpenFuture f = new DefaultOpenFuture(this);
        ChannelListener listener = getChannelListenerProxy();
        try {
            out = new ChannelOutputStream(this, getRemoteWindow(), log, SshConstants.SSH_MSG_CHANNEL_DATA, true);
            authSocket = PropertyResolverUtils.getString(this, SshAgent.SSH_AUTHSOCKET_ENV_NAME);
            pool = Pool.create(AprLibrary.getInstance().getRootPool());
            handle = Local.create(authSocket, pool);
            int result = Local.connect(handle, 0);
            if (result != Status.APR_SUCCESS) {
                throwException(result);
            }

            ExecutorService service = getExecutorService();
            forwardService = (service == null) ? ThreadUtils.newSingleThreadExecutor("ChannelAgentForwarding[" + authSocket + "]") : service;
            shutdownForwarder = (service == forwardService) ? isShutdownOnExit() : true;

            final int copyBufSize = PropertyResolverUtils.getIntProperty(this, FORWARDER_BUFFER_SIZE, DEFAULT_FORWARDER_BUF_SIZE);
            ValidateUtils.checkTrue(copyBufSize >= MIN_FORWARDER_BUF_SIZE, "Copy buf size below min.: %d", copyBufSize);
            ValidateUtils.checkTrue(copyBufSize <= MAX_FORWARDER_BUF_SIZE, "Copy buf size above max.: %d", copyBufSize);

            forwarder = forwardService.submit(new Runnable() {
                @SuppressWarnings("synthetic-access")
                @Override
                public void run() {
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
                }
            });

            listener.channelOpenSuccess(this);
            f.setOpened();
        } catch (Throwable t) {
            Throwable e = GenericUtils.peelException(t);
            try {
                listener.channelOpenFailure(this, e);
            } catch (Throwable err) {
                Throwable ignored = GenericUtils.peelException(err);
                log.warn("doInit({}) failed ({}) to inform listener of open failure={}: {}",
                         this, ignored.getClass().getSimpleName(), e.getClass().getSimpleName(), ignored.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("doInit(" + this + ") inform listener open failure details", ignored);
                }
                if (log.isTraceEnabled()) {
                    Throwable[] suppressed = ignored.getSuppressed();
                    if (GenericUtils.length(suppressed) > 0) {
                        for (Throwable s : suppressed) {
                            log.trace("doInit(" + this + ") suppressed channel open failure signalling", s);
                        }
                    }
                }
            }
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
        Socket.close(handle);

        try {
            if ((forwarder != null) && (!forwarder.isDone())) {
                forwarder.cancel(true);
            }
        } finally {
            forwarder = null;
        }

        try {
            if ((forwardService != null) && shutdownForwarder) {
                Collection<?> runners = forwardService.shutdownNow();
                if (log.isDebugEnabled()) {
                    log.debug("Shut down runners count=" + GenericUtils.size(runners));
                }
            }
        } finally {
            forwardService = null;
            shutdownForwarder = false;
        }
    }

    @Override
    public CloseFuture close(boolean immediately) {
        return super.close(immediately).addListener(new SshFutureListener<CloseFuture>() {
            @SuppressWarnings("synthetic-access")
            @Override
            public void operationComplete(CloseFuture sshFuture) {
                closeImmediately0();
            }
        });
    }

    @Override
    protected void doWriteData(byte[] data, int off, int len) throws IOException {
        int result = Socket.send(handle, data, off, len);
        if (result < Status.APR_SUCCESS) {
            throwException(result);
        }
    }

    @Override
    protected void doWriteExtendedData(byte[] data, int off, int len) throws IOException {
        throw new UnsupportedOperationException("AgentForward channel does not support extended data");
    }

    /**
     * transform an APR error number in a more fancy exception
     *
     * @param code APR error code
     * @throws java.io.IOException the produced exception for the given APR error number
     */
    private static void throwException(int code) throws IOException {
        throw new IOException(org.apache.tomcat.jni.Error.strerror(-code) + " (code: " + code + ")");
    }
}
