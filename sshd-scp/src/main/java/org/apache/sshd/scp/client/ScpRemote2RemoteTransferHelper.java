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

package org.apache.sshd.scp.client;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;

import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.LimitInputStream;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.scp.client.ScpClient.Option;
import org.apache.sshd.scp.common.helpers.AbstractScpCommandDetails;
import org.apache.sshd.scp.common.helpers.ScpIoUtils;
import org.apache.sshd.scp.common.helpers.ScpReceiveFileCommandDetails;
import org.apache.sshd.scp.common.helpers.ScpTimestampCommandDetails;

/**
 * Helps transfer files between 2 servers rather than between server and local file system by using 2
 * {@link ClientSession}-s and simply copying from one server to the other
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpRemote2RemoteTransferHelper extends AbstractLoggingBean {
    protected final ScpRemote2RemoteTransferListener listener;

    private final ClientSession sourceSession;
    private final ClientSession destSession;

    public ScpRemote2RemoteTransferHelper(ClientSession sourceSession, ClientSession destSession) {
        this(sourceSession, destSession, null);
    }

    /**
     * @param sourceSession The source {@link ClientSession}
     * @param destSession   The destination {@link ClientSession}
     * @param listener      An optional {@link ScpRemote2RemoteTransferListener}
     */
    public ScpRemote2RemoteTransferHelper(ClientSession sourceSession, ClientSession destSession,
                                          ScpRemote2RemoteTransferListener listener) {
        this.sourceSession = Objects.requireNonNull(sourceSession, "No source session provided");
        this.destSession = Objects.requireNonNull(destSession, "No destination session provided");
        this.listener = listener;
    }

    public ClientSession getSourceSession() {
        return sourceSession;
    }

    public ClientSession getDestinationSession() {
        return destSession;
    }

    /**
     * Transfers a single file
     *
     * @param  source             Source path in the source session
     * @param  destination        Destination path in the destination session
     * @param  preserveAttributes Whether to preserve the attributes of the transferred file (e.g., permissions, file
     *                            associated timestamps, etc.)
     * @throws IOException        If failed to transfer
     */
    public void transferFile(String source, String destination, boolean preserveAttributes) throws IOException {
        Collection<Option> options = preserveAttributes
                ? Collections.unmodifiableSet(EnumSet.of(Option.PreserveAttributes))
                : Collections.emptySet()
                ;
        executeTransfer(source, options, destination, options);
    }

    protected void executeTransfer(
            String source, Collection<Option> srcOptions,
            String destination, Collection<Option> dstOptions)
            throws IOException {
        String srcCmd = ScpClient.createReceiveCommand(source, srcOptions);
        ClientSession srcSession = getSourceSession();
        ClientSession dstSession = getDestinationSession();
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("executeTransfer({})[srcCmd='{}']) {} => {}",
                    this, srcCmd, source, destination);
        }

        ChannelExec srcChannel = ScpIoUtils.openCommandChannel(srcSession, srcCmd, log);
        try (InputStream srcIn = srcChannel.getInvertedOut();
             OutputStream srcOut = srcChannel.getInvertedIn()) {
            String dstCmd = ScpClient.createSendCommand(destination, dstOptions);
            if (debugEnabled) {
                log.debug("executeTransfer({})[dstCmd='{}'} {} => {}",
                        this, dstCmd, source, destination);
            }

            ChannelExec dstChannel = ScpIoUtils.openCommandChannel(dstSession, dstCmd, log);
            try (InputStream dstIn = dstChannel.getInvertedOut();
                 OutputStream dstOut = dstChannel.getInvertedIn()) {
                int statusCode = transferStatusCode("XFER-CMD", dstIn, srcOut);
                ScpIoUtils.validateCommandStatusCode("XFER-CMD", "executeTransfer", statusCode, false);
                redirectReceivedFile(source, srcIn, srcOut, destination, dstIn, dstOut);
            } finally {
                dstChannel.close(false);
            }
        } finally {
            srcChannel.close(false);
        }

    }

    protected long redirectReceivedFile(
            String source, InputStream srcIn, OutputStream srcOut,
            String destination, InputStream dstIn, OutputStream dstOut)
            throws IOException {
        boolean debugEnabled = log.isDebugEnabled();
        String header = ScpIoUtils.readLine(srcIn, false);
        if (debugEnabled) {
            log.debug("redirectReceivedFile({}) header={}", this, header);
        }

        char cmdName = header.charAt(0);
        ScpTimestampCommandDetails time = null;
        if (cmdName == ScpTimestampCommandDetails.COMMAND_NAME) {
            // Pass along the "T<mtime> 0 <atime> 0" and wait for response
            time = ScpTimestampCommandDetails.parseTime(header);
            // Read the next command - which must be a 'C' command
            header = transferTimestampCommand(source, srcIn, srcOut, destination, dstIn, dstOut, time);
            cmdName = header.charAt(0);
        }

        if (cmdName != ScpReceiveFileCommandDetails.COMMAND_NAME) {
            throw new StreamCorruptedException("Unexpected file command: " + header);
        }

        ScpReceiveFileCommandDetails details = new ScpReceiveFileCommandDetails(header);
        signalReceivedCommand(details);

        // Pass along the "Cmmmm <length> <filename" command and wait for ACK
        ScpIoUtils.writeLine(dstOut, header);
        int statusCode = transferStatusCode(header, dstIn, srcOut);
        ScpIoUtils.validateCommandStatusCode("[DST] " + header, "redirectReceivedFile", statusCode, false);
        // Wait with ACK ready for transfer until ready to transfer data
        long xferCount = transferFileData(source, srcIn, srcOut, destination, dstIn, dstOut, time, details);

        // wait for source to signal data finished and pass it along
        statusCode = transferStatusCode("SRC-EOF", srcIn, dstOut);
        ScpIoUtils.validateCommandStatusCode("[SRC-EOF] " + header, "redirectReceivedFile", statusCode, false);

        // wait for destination to signal data received
        statusCode = ScpIoUtils.readAck(dstIn, false, log, "DST-EOF");
        ScpIoUtils.validateCommandStatusCode("[DST-EOF] " + header, "redirectReceivedFile", statusCode, false);
        return xferCount;
    }

    protected String transferTimestampCommand(
            String source, InputStream srcIn, OutputStream srcOut,
            String destination, InputStream dstIn, OutputStream dstOut,
            ScpTimestampCommandDetails time)
            throws IOException {
        signalReceivedCommand(time);

        String header = time.toHeader();
        ScpIoUtils.writeLine(dstOut, header);
        int statusCode = transferStatusCode(header, dstIn, srcOut);
        ScpIoUtils.validateCommandStatusCode("[DST] " + header, "transferTimestampCommand", statusCode, false);

        header = ScpIoUtils.readLine(srcIn, false);
        if (log.isDebugEnabled()) {
            log.debug("transferTimestampCommand({}) header={}", this, header);
        }

        return header;
    }

    protected int transferStatusCode(Object logHint, InputStream in, OutputStream out) throws IOException {
        int statusCode = in.read();
        if (statusCode == -1) {
            throw new EOFException("readAck(" + logHint + ") - EOF before ACK");
        }

        if (statusCode != ScpIoUtils.OK) {
            String line = ScpIoUtils.readLine(in);
            if (log.isDebugEnabled()) {
                log.debug("transferStatusCode({})[{}] status={}, line='{}'", this, logHint, statusCode, line);
            }
            out.write(statusCode);
            ScpIoUtils.writeLine(out, line);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("transferStatusCode({})[{}] status={}", this, logHint, statusCode);
            }
            out.write(statusCode);
            out.flush();
        }

        return statusCode;
    }

    protected long transferFileData(
            String source, InputStream srcIn, OutputStream srcOut,
            String destination, InputStream dstIn, OutputStream dstOut,
            ScpTimestampCommandDetails time, ScpReceiveFileCommandDetails details)
            throws IOException {
        long length = details.getLength();
        if (length < 0L) { // TODO consider throwing an exception...
            log.warn("transferFileData({})[{} => {}] bad length in header: {}",
                    this, source, destination, details.toHeader());
        }

        ClientSession srcSession = getSourceSession();
        ClientSession dstSession = getDestinationSession();
        if (listener != null) {
            listener.startDirectFileTransfer(srcSession, source, dstSession, destination, time, details);
        }

        long xferCount;
        try (InputStream inputStream = new LimitInputStream(srcIn, length)) {
            ScpIoUtils.ack(srcOut); // ready to receive the data from source
            xferCount = IoUtils.copy(inputStream, dstOut);
            dstOut.flush(); // make sure all data sent to destination
        } catch (IOException | RuntimeException | Error e) {
            if (listener != null) {
                listener.endDirectFileTransfer(srcSession, source, dstSession, destination, time, details, 0L, e);
            }
            throw e;
        }

        if (log.isDebugEnabled()) {
            log.debug("transferFileData({})[{} => {}] xfer {}/{} for {}",
                    this, source, destination, xferCount, length, details.getName());
        }
        if (listener != null) {
            listener.endDirectFileTransfer(srcSession, source, dstSession, destination, time, details, xferCount, null);
        }

        return xferCount;
    }

    // Useful "hook" for implementors
    protected void signalReceivedCommand(AbstractScpCommandDetails details) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("signalReceivedCommand({}) {}", this, details.toHeader());
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[src=" + getSourceSession() + ",dst=" + getDestinationSession() + "]";
    }
}
