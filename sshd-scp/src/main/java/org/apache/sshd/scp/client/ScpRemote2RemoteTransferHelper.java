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
import java.util.Set;

import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.util.SelectorUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.LimitInputStream;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.scp.client.ScpClient.Option;
import org.apache.sshd.scp.common.helpers.AbstractScpCommandDetails;
import org.apache.sshd.scp.common.helpers.ScpAckInfo;
import org.apache.sshd.scp.common.helpers.ScpDirEndCommandDetails;
import org.apache.sshd.scp.common.helpers.ScpIoUtils;
import org.apache.sshd.scp.common.helpers.ScpPathCommandDetailsSupport;
import org.apache.sshd.scp.common.helpers.ScpReceiveDirCommandDetails;
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
                : Collections.emptySet();
        executeTransfer(source, options, destination, options);
    }

    /**
     * Transfers a directory
     *
     * @param  source             Source path in the source session
     * @param  destination        Destination path in the destination session
     * @param  preserveAttributes Whether to preserve the attributes of the transferred file (e.g., permissions, file
     *                            associated timestamps, etc.)
     * @throws IOException        If failed to transfer
     */
    public void transferDirectory(String source, String destination, boolean preserveAttributes)
            throws IOException {
        Set<Option> options = EnumSet.of(Option.TargetIsDirectory, Option.Recursive);
        if (preserveAttributes) {
            options.add(Option.PreserveAttributes);
        }

        options = Collections.unmodifiableSet(options);
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
                ScpAckInfo ackInfo = transferStatusCode("XFER-CMD", dstIn, srcOut);
                ackInfo.validateCommandStatusCode("XFER-CMD", "executeTransfer");

                if (srcOptions.contains(Option.TargetIsDirectory) || dstOptions.contains(Option.TargetIsDirectory)) {
                    redirectDirectoryTransfer(source, srcIn, srcOut, destination, dstIn, dstOut, 0);
                } else {
                    redirectFileTransfer(source, srcIn, srcOut, destination, dstIn, dstOut);
                }
            } finally {
                dstChannel.close(false);
            }
        } finally {
            srcChannel.close(false);
        }
    }

    protected long redirectFileTransfer(
            String source, InputStream srcIn, OutputStream srcOut,
            String destination, InputStream dstIn, OutputStream dstOut)
            throws IOException {
        Object data = receiveNextCmd("redirectFileTransfer", srcIn);
        if (data instanceof ScpAckInfo) {
            throw new StreamCorruptedException("Unexpected ACK instead of header: " + data);
        }

        boolean debugEnabled = log.isDebugEnabled();
        String header = (String) data;
        if (debugEnabled) {
            log.debug("redirectFileTransfer({}) {} => {}: header={}", this, source, destination, header);
        }

        ScpTimestampCommandDetails time = null;
        if (header.charAt(0) == ScpTimestampCommandDetails.COMMAND_NAME) {
            // Pass along the "T<mtime> 0 <atime> 0" and wait for response
            time = new ScpTimestampCommandDetails(header);
            signalReceivedCommand(time);

            header = transferTimestampCommand(source, srcIn, srcOut, destination, dstIn, dstOut, header);
            if (debugEnabled) {
                log.debug("redirectFileTransfer({}) {} => {}: header={}", this, source, destination, header);
            }
        }

        return handleFileTransferRequest(source, srcIn, srcOut, destination, dstIn, dstOut, time, header);
    }

    protected long handleFileTransferRequest(
            String source, InputStream srcIn, OutputStream srcOut,
            String destination, InputStream dstIn, OutputStream dstOut,
            ScpTimestampCommandDetails fileTime, String header)
            throws IOException {
        if (header.charAt(0) != ScpReceiveFileCommandDetails.COMMAND_NAME) {
            throw new IllegalArgumentException("Invalid file transfer request: " + header);
        }

        ScpIoUtils.writeLine(dstOut, header);
        ScpAckInfo ackInfo = transferStatusCode(header, dstIn, srcOut);
        ackInfo.validateCommandStatusCode("[DST] " + header, "handleFileTransferRequest");

        ScpReceiveFileCommandDetails fileDetails = new ScpReceiveFileCommandDetails(header);
        signalReceivedCommand(fileDetails);

        ClientSession srcSession = getSourceSession();
        ClientSession dstSession = getDestinationSession();
        if (listener != null) {
            listener.startDirectFileTransfer(srcSession, source, dstSession, destination, fileTime, fileDetails);
        }

        long xferCount;
        try {
            xferCount = transferSimpleFile(source, srcIn, srcOut, destination, dstIn, dstOut, header, fileDetails.getLength());
        } catch (IOException | RuntimeException | Error e) {
            if (listener != null) {
                listener.endDirectFileTransfer(srcSession, source, dstSession, destination, fileTime, fileDetails, 0L, e);
            }
            throw e;
        }

        if (listener != null) {
            listener.endDirectFileTransfer(srcSession, source, dstSession, destination, fileTime, fileDetails, xferCount, null);
        }

        return xferCount;
    }

    protected void redirectDirectoryTransfer(
            String source, InputStream srcIn, OutputStream srcOut,
            String destination, InputStream dstIn, OutputStream dstOut,
            int depth)
            throws IOException {
        Object data = receiveNextCmd("redirectDirectoryTransfer", srcIn);
        if (data instanceof ScpAckInfo) {
            throw new StreamCorruptedException("Unexpected ACK instead of header: " + data);
        }

        String header = (String) data;
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("redirectDirectoryTransfer({})[depth={}] {} => {}: header={}",
                    this, depth, source, destination, header);
        }

        ScpTimestampCommandDetails time = null;
        if (header.charAt(0) == ScpTimestampCommandDetails.COMMAND_NAME) {
            // Pass along the "T<mtime> 0 <atime> 0" and wait for response
            time = new ScpTimestampCommandDetails(header);
            signalReceivedCommand(time);

            header = transferTimestampCommand(source, srcIn, srcOut, destination, dstIn, dstOut, header);
            if (debugEnabled) {
                log.debug("redirectDirectoryTransfer({})[depth={}] {} => {}: header={}",
                        this, depth, source, destination, header);
            }
        }

        handleDirectoryTransferRequest(source, srcIn, srcOut, destination, dstIn, dstOut, depth, time, header);
    }

    @SuppressWarnings("checkstyle:ParameterNumber")
    protected void handleDirectoryTransferRequest(
            String srcPath, InputStream srcIn, OutputStream srcOut,
            String dstPath, InputStream dstIn, OutputStream dstOut,
            int depth, ScpTimestampCommandDetails dirTime, String header)
            throws IOException {
        if (header.charAt(0) != ScpReceiveDirCommandDetails.COMMAND_NAME) {
            throw new IllegalArgumentException("Invalid file transfer request: " + header);
        }

        ScpIoUtils.writeLine(dstOut, header);
        ScpAckInfo ackInfo = transferStatusCode(header, dstIn, srcOut);
        ackInfo.validateCommandStatusCode("[DST@" + depth + "] " + header, "handleDirectoryTransferRequest");

        ScpReceiveDirCommandDetails dirDetails = new ScpReceiveDirCommandDetails(header);
        signalReceivedCommand(dirDetails);

        String dirName = dirDetails.getName();
        // 1st command refers to the first path component of the original source/destination
        String source = (depth == 0) ? srcPath : SelectorUtils.concatPaths(srcPath, dirName, '/');
        String destination = (depth == 0) ? dstPath : SelectorUtils.concatPaths(dstPath, dirName, '/');

        ClientSession srcSession = getSourceSession();
        ClientSession dstSession = getDestinationSession();
        if (listener != null) {
            listener.startDirectDirectoryTransfer(srcSession, source, dstSession, destination, dirTime, dirDetails);
        }

        try {
            for (boolean debugEnabled = log.isDebugEnabled(), dirEndSignal = false;
                 !dirEndSignal;
                 debugEnabled = log.isDebugEnabled()) {
                Object data = receiveNextCmd("handleDirectoryTransferRequest", srcIn);
                if (data instanceof ScpAckInfo) {
                    throw new StreamCorruptedException("Unexpected ACK instead of header: " + data);
                }

                header = (String) data;
                if (debugEnabled) {
                    log.debug("handleDirectoryTransferRequest({})[depth={}] {} => {}: header={}",
                            this, depth, source, destination, header);
                }

                ScpTimestampCommandDetails time = null;
                char cmdName = header.charAt(0);
                if (cmdName == ScpTimestampCommandDetails.COMMAND_NAME) {
                    // Pass along the "T<mtime> 0 <atime> 0" and wait for response
                    time = new ScpTimestampCommandDetails(header);
                    signalReceivedCommand(time);

                    header = transferTimestampCommand(source, srcIn, srcOut, destination, dstIn, dstOut, header);
                    if (debugEnabled) {
                        log.debug("handleDirectoryTransferRequest({})[depth={}] {} => {}: header={}",
                                this, depth, source, destination, header);
                    }
                    cmdName = header.charAt(0);
                }

                switch (cmdName) {
                    case ScpReceiveFileCommandDetails.COMMAND_NAME:
                    case ScpReceiveDirCommandDetails.COMMAND_NAME: {
                        ScpPathCommandDetailsSupport subPathDetails = (cmdName == ScpReceiveFileCommandDetails.COMMAND_NAME)
                                ? new ScpReceiveFileCommandDetails(header)
                                : new ScpReceiveDirCommandDetails(header);
                        String name = subPathDetails.getName();
                        String srcSubPath = SelectorUtils.concatPaths(source, name, '/');
                        String dstSubPath = SelectorUtils.concatPaths(destination, name, '/');
                        if (cmdName == ScpReceiveFileCommandDetails.COMMAND_NAME) {
                            handleFileTransferRequest(srcSubPath, srcIn, srcOut, dstSubPath, dstIn, dstOut, time, header);
                        } else {
                            handleDirectoryTransferRequest(srcSubPath, srcIn, srcOut, dstSubPath, dstIn, dstOut, depth + 1,
                                    time, header);
                        }
                        break;
                    }

                    case ScpDirEndCommandDetails.COMMAND_NAME: {
                        ScpIoUtils.writeLine(dstOut, header);
                        ackInfo = transferStatusCode(header, dstIn, srcOut);
                        ackInfo.validateCommandStatusCode("[DST@" + depth + "] " + header, "handleDirectoryTransferRequest");

                        ScpDirEndCommandDetails details = ScpDirEndCommandDetails.parse(header);
                        signalReceivedCommand(details);
                        dirEndSignal = true;
                        break;
                    }

                    default:
                        throw new StreamCorruptedException("Unexpected file command: " + header);
                }
            }
        } catch (IOException | RuntimeException | Error e) {
            if (listener != null) {
                listener.endDirectDirectoryTransfer(srcSession, source, dstSession, destination, dirTime, dirDetails, e);
            }
            throw e;
        }

        if (listener != null) {
            listener.endDirectDirectoryTransfer(srcSession, source, dstSession, destination, dirTime, dirDetails, null);
        }
    }

    protected long transferSimpleFile(
            String source, InputStream srcIn, OutputStream srcOut,
            String destination, InputStream dstIn, OutputStream dstOut,
            String header, long length)
            throws IOException {
        if (length < 0L) { // TODO consider throwing an exception...
            log.warn("transferSimpleFile({})[{} => {}] bad length in header: {}",
                    this, source, destination, header);
        }

        long xferCount;
        try (InputStream inputStream = new LimitInputStream(srcIn, length)) {
            ScpAckInfo.sendOk(srcOut); // ready to receive the data from source
            xferCount = IoUtils.copy(inputStream, dstOut);
            dstOut.flush(); // make sure all data sent to destination
        }

        if (log.isDebugEnabled()) {
            log.debug("transferSimpleFile({})[{} => {}] xfer {}/{}",
                    this, source, destination, xferCount, length);
        }

        // wait for source to signal data finished and pass it along
        ScpAckInfo ackInfo = transferStatusCode("SRC-EOF", srcIn, dstOut);
        ackInfo.validateCommandStatusCode("[SRC-EOF] " + header, "transferSimpleFile");

        // wait for destination to signal data received
        ackInfo = ScpAckInfo.readAck(dstIn, false);
        ackInfo.validateCommandStatusCode("[DST-EOF] " + header, "transferSimpleFile");
        return xferCount;
    }

    protected String transferTimestampCommand(
            String source, InputStream srcIn, OutputStream srcOut,
            String destination, InputStream dstIn, OutputStream dstOut,
            String header)
            throws IOException {
        ScpIoUtils.writeLine(dstOut, header);
        ScpAckInfo ackInfo = transferStatusCode(header, dstIn, srcOut);
        ackInfo.validateCommandStatusCode("[DST] " + header, "transferTimestampCommand");

        Object data = receiveNextCmd("transferTimestampCommand", srcIn);
        if (data instanceof ScpAckInfo) {
            throw new StreamCorruptedException("Unexpected ACK instead of header: " + data);
        }
        return (String) data;
    }

    protected ScpAckInfo transferStatusCode(Object logHint, InputStream in, OutputStream out) throws IOException {
        ScpAckInfo ackInfo = ScpAckInfo.readAck(in, false);
        if (log.isDebugEnabled()) {
            log.debug("transferStatusCode({})[{}] {}", this, logHint, ackInfo);
        }
        ackInfo.send(out);
        return ackInfo;
    }

    // NOTE: we rely on the fact that an SCP command does not start with an ACK code
    protected Object receiveNextCmd(Object logHint, InputStream in) throws IOException {
        int c = in.read();
        if (c == -1) {
            throw new EOFException(logHint + " - premature EOF while waiting for next command");
        }

        if (c == ScpAckInfo.OK) {
            if (log.isDebugEnabled()) {
                log.debug("receiveNextCmd({})[{}] - ACK={}", this, logHint, c);
            }
            return new ScpAckInfo(c);
        }

        String line = ScpIoUtils.readLine(in, false);
        if ((c == ScpAckInfo.WARNING) || (c == ScpAckInfo.ERROR)) {
            if (log.isDebugEnabled()) {
                log.debug("receiveNextCmd({})[{}] - ACK={}", this, logHint, new ScpAckInfo(c, line));
            }
            return new ScpAckInfo(c, line);
        }

        return Character.toString((char) c) + line;
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
