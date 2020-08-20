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
package org.apache.sshd.scp.server;

import java.io.IOException;
import java.util.Collections;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.scp.common.ScpException;
import org.apache.sshd.scp.common.ScpFileOpener;
import org.apache.sshd.scp.common.ScpHelper;
import org.apache.sshd.scp.common.ScpTransferEventListener;
import org.apache.sshd.scp.common.helpers.DefaultScpFileOpener;
import org.apache.sshd.scp.common.helpers.ScpAckInfo;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.AbstractFileSystemCommand;
import org.apache.sshd.server.session.ServerSession;

/**
 * This commands provide SCP support on both server and client side. Permissions and preservation of access /
 * modification times on files are not supported.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpCommand extends AbstractFileSystemCommand {
    protected final int sendBufferSize;
    protected final int receiveBufferSize;
    protected final ScpFileOpener opener;
    protected boolean optR;
    protected boolean optT;
    protected boolean optF;
    protected boolean optD;
    protected boolean optP; // TODO: handle modification times
    protected String path;
    protected IOException error;
    protected ScpTransferEventListener listener;

    /**
     * @param command         The command to be executed
     * @param executorService An {@link CloseableExecutorService} to be used when
     *                        {@code start(ChannelSession, Environment)}-ing execution. If {@code null} an ad-hoc
     *                        single-threaded service is created and used.
     * @param sendSize        Size (in bytes) of buffer to use when sending files
     * @param receiveSize     Size (in bytes) of buffer to use when receiving files
     * @param fileOpener      The {@link ScpFileOpener} - if {@code null} then {@link DefaultScpFileOpener} is used
     * @param eventListener   An {@link ScpTransferEventListener} - may be {@code null}
     * @see                   ThreadUtils#newSingleThreadExecutor(String)
     * @see                   ScpHelper#MIN_SEND_BUFFER_SIZE
     * @see                   ScpHelper#MIN_RECEIVE_BUFFER_SIZE
     */
    public ScpCommand(String command,
                      CloseableExecutorService executorService,
                      int sendSize, int receiveSize,
                      ScpFileOpener fileOpener, ScpTransferEventListener eventListener) {
        super(command, executorService);

        if (sendSize < ScpHelper.MIN_SEND_BUFFER_SIZE) {
            throw new IllegalArgumentException(
                    "<ScpCommmand>(" + command + ") send buffer size "
                                               + "(" + sendSize + ") below minimum required "
                                               + "(" + ScpHelper.MIN_SEND_BUFFER_SIZE + ")");
        }
        sendBufferSize = sendSize;

        if (receiveSize < ScpHelper.MIN_RECEIVE_BUFFER_SIZE) {
            throw new IllegalArgumentException(
                    "<ScpCommmand>(" + command + ") receive buffer size "
                                               + "(" + sendSize + ") below minimum required "
                                               + "(" + ScpHelper.MIN_RECEIVE_BUFFER_SIZE + ")");
        }
        receiveBufferSize = receiveSize;

        opener = (fileOpener == null) ? DefaultScpFileOpener.INSTANCE : fileOpener;
        listener = (eventListener == null) ? ScpTransferEventListener.EMPTY : eventListener;

        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("Executing command {}", command);
        }

        String[] args = GenericUtils.split(command, ' ');
        int numArgs = GenericUtils.length(args);
        for (int i = 1; i < numArgs; i++) {
            String argVal = args[i];
            if (argVal.charAt(0) == '-') {
                for (int j = 1; j < argVal.length(); j++) {
                    char option = argVal.charAt(j);
                    switch (option) {
                        case 'f':
                            optF = true;
                            break;
                        case 'p':
                            optP = true;
                            break;
                        case 'r':
                            optR = true;
                            break;
                        case 't':
                            optT = true;
                            break;
                        case 'd':
                            optD = true;
                            break;
                        default: // ignored
                            if (debugEnabled) {
                                log.debug("Unknown flag ('{}') in command={}", option, command);
                            }
                    }
                }
            } else {
                String prevArg = args[i - 1];
                path = command.substring(command.indexOf(prevArg) + prevArg.length() + 1);

                int pathLen = path.length();
                char startDelim = path.charAt(0);
                char endDelim = (pathLen > 2) ? path.charAt(pathLen - 1) : '\0';
                // remove quotes
                if ((pathLen > 2) && (startDelim == endDelim) && ((startDelim == '\'') || (startDelim == '"'))) {
                    path = path.substring(1, pathLen - 1);
                }
                break;
            }
        }

        if ((!optF) && (!optT)) {
            error = new IOException("Either -f or -t option should be set for " + command);
        }
    }

    @Override
    public void start(ChannelSession channel, Environment env) throws IOException {
        if (error != null) {
            throw error;
        }
        super.start(channel, env);
    }

    @Override
    public void run() {
        int exitValue = ScpAckInfo.OK;
        String exitMessage = null;
        ServerSession session = getServerSession();
        String command = getCommand();
        ScpHelper helper = new ScpHelper(
                session, getInputStream(), getOutputStream(), fileSystem, opener, listener);
        try {
            if (optT) {
                helper.receive(helper.resolveLocalPath(path), optR, optD, optP, receiveBufferSize);
            } else if (optF) {
                helper.send(Collections.singletonList(path), optR, optP, sendBufferSize);
            } else {
                throw new IOException("Unsupported mode");
            }
        } catch (IOException e) {
            boolean debugEnabled = log.isDebugEnabled();
            try {
                Integer statusCode = null;
                if (e instanceof ScpException) {
                    statusCode = ((ScpException) e).getExitStatus();
                }
                exitValue = (statusCode == null) ? ScpAckInfo.ERROR : statusCode;
                // this is an exception so status cannot be OK/WARNING
                if ((exitValue == ScpAckInfo.OK) || (exitValue == ScpAckInfo.WARNING)) {
                    if (debugEnabled) {
                        log.debug("run({})[{}] normalize status code={}", session, command, exitValue);
                    }
                    exitValue = ScpAckInfo.ERROR;
                }
                exitMessage = GenericUtils.trimToEmpty(e.getMessage());
                writeCommandResponseMessage(command, exitValue, exitMessage);
            } catch (IOException e2) {
                error("run({})[{}] Failed ({}) to send error response: {}",
                        session, command, e.getClass().getSimpleName(), e.getMessage(), e2);
            }

            error("run({})[{}] Failed ({}) to run command: {}",
                    session, command, e.getClass().getSimpleName(), e.getMessage(), e);
        } finally {
            ExitCallback callback = getExitCallback();
            if (callback != null) {
                callback.onExit(exitValue, GenericUtils.trimToEmpty(exitMessage));
            }
        }
    }

    protected void writeCommandResponseMessage(String command, int exitValue, String exitMessage) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("writeCommandResponseMessage({}) command='{}', exit-status={}: {}",
                    getServerSession(), command, exitValue, exitMessage);
        }
        ScpAckInfo.sendAck(getOutputStream(), exitValue, exitMessage);
    }

    @Override
    public String toString() {
        return super.toString() + "[" + getSession() + "]";
    }
}
