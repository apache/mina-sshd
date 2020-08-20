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

package org.apache.sshd.scp.common.helpers;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.scp.ScpModuleProperties;
import org.apache.sshd.scp.common.ScpException;
import org.slf4j.Logger;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class ScpIoUtils {
    public static final Set<ClientChannelEvent> COMMAND_WAIT_EVENTS
            = Collections.unmodifiableSet(EnumSet.of(ClientChannelEvent.EXIT_STATUS, ClientChannelEvent.CLOSED));

    private ScpIoUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    public static String readLine(InputStream in) throws IOException {
        return readLine(in, false);
    }

    public static String readLine(InputStream in, boolean canEof) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(Byte.MAX_VALUE)) {
            for (;;) {
                int c = in.read();
                if (c == '\n') {
                    return baos.toString(StandardCharsets.UTF_8.name());
                } else if (c == -1) {
                    if (!canEof) {
                        throw new EOFException("EOF while await end of line");
                    }
                    return null;
                } else {
                    baos.write(c);
                }
            }
        }
    }

    public static void writeLine(OutputStream out, String cmd) throws IOException {
        if (cmd != null) {
            out.write(cmd.getBytes(StandardCharsets.UTF_8));
        }
        out.write('\n');
        out.flush();
    }

    public static ScpAckInfo sendAcknowledgedCommand(AbstractScpCommandDetails cmd, InputStream in, OutputStream out)
            throws IOException {
        return sendAcknowledgedCommand(cmd.toHeader(), in, out);
    }

    public static ScpAckInfo sendAcknowledgedCommand(String cmd, InputStream in, OutputStream out) throws IOException {
        writeLine(out, cmd);
        return ScpAckInfo.readAck(in, false);
    }

    public static String getExitStatusName(Integer exitStatus) {
        if (exitStatus == null) {
            return "null";
        }

        switch (exitStatus) {
            case ScpAckInfo.OK:
                return "OK";
            case ScpAckInfo.WARNING:
                return "WARNING";
            case ScpAckInfo.ERROR:
                return "ERROR";
            default:
                return exitStatus.toString();
        }
    }

    public static ChannelExec openCommandChannel(ClientSession session, String cmd, Logger log) throws IOException {
        Duration waitTimeout = ScpModuleProperties.SCP_EXEC_CHANNEL_OPEN_TIMEOUT.getRequired(session);
        ChannelExec channel = session.createExecChannel(cmd);

        long startTime = System.nanoTime();
        try {
            channel.open().verify(waitTimeout);
            long endTime = System.nanoTime();
            long nanosWait = endTime - startTime;
            if ((log != null) && log.isTraceEnabled()) {
                log.trace("openCommandChannel(" + session + ")[" + cmd + "]"
                          + " completed after " + nanosWait
                          + " nanos out of " + waitTimeout.toNanos());
            }

            return channel;
        } catch (IOException | RuntimeException e) {
            long endTime = System.nanoTime();
            long nanosWait = endTime - startTime;
            if ((log != null) && log.isTraceEnabled()) {
                log.trace("openCommandChannel(" + session + ")[" + cmd + "]"
                          + " failed (" + e.getClass().getSimpleName() + ")"
                          + " to complete after " + nanosWait
                          + " nanos out of " + waitTimeout.toNanos()
                          + ": " + e.getMessage());
            }

            channel.close(false);
            throw e;
        }
    }

    /**
     * Invoked by the various <code>upload/download</code> methods after having successfully completed the remote copy
     * command and (optionally) having received an exit status from the remote server. If no exit status received within
     * {@link CoreModuleProperties#CHANNEL_CLOSE_TIMEOUT} the no further action is taken. Otherwise, the exit status is
     * examined to ensure it is either OK or WARNING - if not, an {@link ScpException} is thrown
     *
     * @param  session     The associated {@link ClientSession}
     * @param  cmd         The attempted remote copy command
     * @param  channel     The {@link ClientChannel} through which the command was sent - <B>Note:</B> then channel may
     *                     be in the process of being closed
     * @param  handler     The {@link CommandStatusHandler} to invoke once the exit status is received. if {@code null}
     *                     then {@link #handleCommandExitStatus(ClientSession, String, Integer, Logger)} is called
     * @param  log         An optional {@link Logger} to use for issuing log messages - ignored if {@code null}
     * @throws IOException If failed the command
     */
    public static void handleCommandExitStatus(
            ClientSession session, String cmd, ClientChannel channel, CommandStatusHandler handler, Logger log)
            throws IOException {
        // give a chance for the exit status to be received
        Duration timeout = ScpModuleProperties.SCP_EXEC_CHANNEL_EXIT_STATUS_TIMEOUT.getRequired(channel);
        if (GenericUtils.isNegativeOrNull(timeout)) {
            if (handler == null) {
                handleCommandExitStatus(session, cmd, null, log);
            } else {
                handler.handleCommandExitStatus(session, cmd, (Integer) null);
            }
            return;
        }

        long waitStart = System.nanoTime();
        Collection<ClientChannelEvent> events = channel.waitFor(COMMAND_WAIT_EVENTS, timeout);
        long waitEnd = System.nanoTime();
        if ((log != null) && log.isDebugEnabled()) {
            log.debug("handleCommandExitStatus({}) cmd='{}', waited={} nanos, events={}",
                    session, cmd, waitEnd - waitStart, events);
        }

        /*
         * There are sometimes race conditions in the order in which channels are closed and exit-status sent by the
         * remote peer (if at all), thus there is no guarantee that we will have an exit status here
         */
        Integer exitStatus = channel.getExitStatus();
        if (handler == null) {
            handleCommandExitStatus(session, cmd, exitStatus, log);
        } else {
            handler.handleCommandExitStatus(session, cmd, exitStatus);
        }
    }

    /**
     * Invoked by the various <code>upload/download</code> methods after having successfully completed the remote copy
     * command and (optionally) having received an exit status from the remote server
     *
     * @param  session     The associated {@link ClientSession}
     * @param  cmd         The attempted remote copy command
     * @param  exitStatus  The exit status - if {@code null} then no status was reported
     * @param  log         An optional {@link Logger} to use for issuing log messages - ignored if {@code null}
     * @throws IOException If got a an error exit status
     */
    public static void handleCommandExitStatus(
            ClientSession session, String cmd, Integer exitStatus, Logger log)
            throws IOException {
        if ((log != null) && log.isDebugEnabled()) {
            log.debug("handleCommandExitStatus({}) cmd='{}', exit-status={}",
                    session, cmd, ScpIoUtils.getExitStatusName(exitStatus));
        }

        if (exitStatus == null) {
            return;
        }

        int statusCode = exitStatus;
        switch (statusCode) {
            case ScpAckInfo.OK: // do nothing
                break;
            case ScpAckInfo.WARNING:
                if (log != null) {
                    log.warn("handleCommandExitStatus({}) cmd='{}' may have terminated with some problems", session, cmd);
                }
                break;
            default:
                throw new ScpException(
                        "Failed to run command='" + cmd + "': " + ScpIoUtils.getExitStatusName(exitStatus), exitStatus);
        }
    }

}
