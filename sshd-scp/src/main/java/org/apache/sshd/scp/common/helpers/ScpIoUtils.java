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
    // ACK status codes
    public static final int OK = 0;
    public static final int WARNING = 1;
    public static final int ERROR = 2;

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
        out.write(cmd.getBytes(StandardCharsets.UTF_8));
        out.write('\n');
        out.flush();
    }

    /**
     * Sends the &quot;T...&quot; command and waits for ACK
     *
     * @param  in          The {@link InputStream} to read from
     * @param  out         The target {@link OutputStream}
     * @param  time        The {@link ScpTimestampCommandDetails} value to send
     * @param  log         An optional {@link Logger} to use for issuing log messages - ignored if {@code null}
     * @param  logHint     An optional hint to be used in the logged messages to identifier the caller's context
     * @return             The read ACK value
     * @throws IOException If failed to complete the read/write cyle
     */
    public static int sendTimeCommand(
            InputStream in, OutputStream out, ScpTimestampCommandDetails time, Logger log, Object logHint)
            throws IOException {
        String cmd = time.toHeader();
        if ((log != null) && log.isDebugEnabled()) {
            log.debug("sendTimeCommand({}) send timestamp={} command: {}", logHint, time, cmd);
        }
        writeLine(out, cmd);

        return readAck(in, false, log, logHint);
    }

    /**
     * Reads a single ACK from the input
     *
     * @param  in          The {@link InputStream} to read from
     * @param  canEof      If {@code true} then OK if EOF is received before full ACK received
     * @param  log         An optional {@link Logger} to use for issuing log messages - ignored if {@code null}
     * @param  logHint     An optional hint to be used in the logged messages to identifier the caller's context
     * @return             The read ACK value
     * @throws IOException If failed to complete the read
     */
    public static int readAck(InputStream in, boolean canEof, Logger log, Object logHint) throws IOException {
        int c = in.read();
        boolean debugEnabled = (log != null) && log.isDebugEnabled();
        switch (c) {
            case -1:
                if (debugEnabled) {
                    log.debug("readAck({})[EOF={}] received EOF", logHint, canEof);
                }
                if (!canEof) {
                    throw new EOFException("readAck - EOF before ACK");
                }
                break;
            case OK:
                if (debugEnabled) {
                    log.debug("readAck({})[EOF={}] read OK", logHint, canEof);
                }
                break;
            case WARNING: {
                if (debugEnabled) {
                    log.debug("readAck({})[EOF={}] read warning message", logHint, canEof);
                }

                String line = readLine(in);
                if (log != null) {
                    log.warn("readAck({})[EOF={}] - Received warning: {}", logHint, canEof, line);
                }
                break;
            }
            case ERROR: {
                if (debugEnabled) {
                    log.debug("readAck({})[EOF={}] read error message", logHint, canEof);
                }
                String line = readLine(in);
                if (debugEnabled) {
                    log.debug("readAck({})[EOF={}] received error: {}", logHint, canEof, line);
                }
                throw new ScpException("Received nack: " + line, c);
            }
            default:
                break;
        }

        return c;
    }

    public static int sendAcknowledgedCommand(
            String cmd, InputStream in, OutputStream out, Logger log)
            throws IOException {
        writeLine(out, cmd);
        return readAck(in, false, log, cmd);
    }

    /**
     * Sends {@link #OK} ACK code
     *
     * @param  out         The target {@link OutputStream}
     * @throws IOException If failed to send the ACK code
     */
    public static void ack(OutputStream out) throws IOException {
        out.write(OK);
        out.flush();
    }

    public static <O extends OutputStream> O sendWarning(O out, String message) throws IOException {
        return sendResponseMessage(out, WARNING, message);
    }

    public static <O extends OutputStream> O sendError(O out, String message) throws IOException {
        return sendResponseMessage(out, ERROR, message);
    }

    public static <O extends OutputStream> O sendResponseMessage(O out, int level, String message) throws IOException {
        out.write(level);
        writeLine(out, message);
        return out;
    }

    public static void validateCommandStatusCode(String command, Object location, int statusCode, boolean eofAllowed)
            throws IOException {
        switch (statusCode) {
            case -1:
                if (!eofAllowed) {
                    throw new EOFException("Unexpected EOF for command='" + command + "' on " + location);
                }
                break;
            case OK:
                break;
            case WARNING:
                break;
            default:
                throw new ScpException(
                        "Bad reply code (" + statusCode + ") for command='" + command + "' on " + location, statusCode);
        }
    }

    public static String getExitStatusName(Integer exitStatus) {
        if (exitStatus == null) {
            return "null";
        }

        switch (exitStatus) {
            case OK:
                return "OK";
            case WARNING:
                return "WARNING";
            case ERROR:
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
            case OK: // do nothing
                break;
            case WARNING:
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
