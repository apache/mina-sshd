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
package org.apache.sshd.scp.common;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

import org.apache.sshd.common.file.util.MockPath;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.LimitInputStream;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.scp.common.ScpTransferEventListener.FileOperation;
import org.apache.sshd.scp.common.helpers.DefaultScpFileOpener;
import org.apache.sshd.scp.common.helpers.ScpDirEndCommandDetails;
import org.apache.sshd.scp.common.helpers.ScpIoUtils;
import org.apache.sshd.scp.common.helpers.ScpPathCommandDetailsSupport;
import org.apache.sshd.scp.common.helpers.ScpReceiveDirCommandDetails;
import org.apache.sshd.scp.common.helpers.ScpReceiveFileCommandDetails;
import org.apache.sshd.scp.common.helpers.ScpTimestampCommandDetails;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpHelper extends AbstractLoggingBean implements SessionHolder<Session> {
    /**
     * Command prefix used to identify SCP commands
     */
    public static final String SCP_COMMAND_PREFIX = "scp";

    /**
     * Default size (in bytes) of send / receive buffer size
     */
    public static final int DEFAULT_COPY_BUFFER_SIZE = IoUtils.DEFAULT_COPY_SIZE;
    public static final int DEFAULT_RECEIVE_BUFFER_SIZE = DEFAULT_COPY_BUFFER_SIZE;
    public static final int DEFAULT_SEND_BUFFER_SIZE = DEFAULT_COPY_BUFFER_SIZE;

    /**
     * The minimum size for sending / receiving files
     */
    public static final int MIN_COPY_BUFFER_SIZE = Byte.MAX_VALUE;
    public static final int MIN_RECEIVE_BUFFER_SIZE = MIN_COPY_BUFFER_SIZE;
    public static final int MIN_SEND_BUFFER_SIZE = MIN_COPY_BUFFER_SIZE;

    protected final InputStream in;
    protected final OutputStream out;
    protected final FileSystem fileSystem;
    protected final ScpFileOpener opener;
    protected final ScpTransferEventListener listener;

    private final Session sessionInstance;

    public ScpHelper(Session session, InputStream in, OutputStream out, FileSystem fileSystem, ScpFileOpener opener,
                     ScpTransferEventListener eventListener) {
        this.sessionInstance = Objects.requireNonNull(session, "No session");
        this.in = Objects.requireNonNull(in, "No input stream");
        this.out = Objects.requireNonNull(out, "No output stream");
        this.fileSystem = fileSystem;
        this.opener = (opener == null) ? DefaultScpFileOpener.INSTANCE : opener;
        this.listener = (eventListener == null) ? ScpTransferEventListener.EMPTY : eventListener;
    }

    @Override
    public Session getSession() {
        return sessionInstance;
    }

    public void receiveFileStream(OutputStream local, int bufferSize) throws IOException {
        receive((session, line, isDir, timestamp) -> {
            if (isDir) {
                throw new StreamCorruptedException("Cannot download a directory into a file stream: " + line);
            }

            Path path = new MockPath(line);
            receiveStream(line, new ScpTargetStreamResolver() {
                @Override
                @SuppressWarnings("synthetic-access") // see
                                                     // https://bugs.eclipse.org/bugs/show_bug.cgi?id=537593
                public OutputStream resolveTargetStream(
                        Session session, String name, long length,
                        Set<PosixFilePermission> perms, OpenOption... options)
                        throws IOException {
                    if (log.isDebugEnabled()) {
                        log.debug("resolveTargetStream({}) name={}, perms={}, len={} - started local stream download",
                                ScpHelper.this, name, perms, length);
                    }
                    return local;
                }

                @Override
                public Path getEventListenerFilePath() {
                    return path;
                }

                @Override
                @SuppressWarnings("synthetic-access") // see
                                                     // https://bugs.eclipse.org/bugs/show_bug.cgi?id=537593
                public void postProcessReceivedData(
                        String name, boolean preserve, Set<PosixFilePermission> perms,
                        ScpTimestampCommandDetails time)
                        throws IOException {
                    if (log.isDebugEnabled()) {
                        log.debug("postProcessReceivedData({}) name={}, perms={}, preserve={} time={}", ScpHelper.this,
                                name, perms, preserve, time);
                    }
                }

                @Override
                public String toString() {
                    return line;
                }
            }, timestamp, false, bufferSize);
        });
    }

    public void receive(Path local, boolean recursive, boolean shouldBeDir, boolean preserve, int bufferSize)
            throws IOException {
        Path localPath = Objects.requireNonNull(local, "No local path").normalize().toAbsolutePath();
        Path path = opener.resolveIncomingReceiveLocation(getSession(), localPath, recursive, shouldBeDir, preserve);
        receive((session, line, isDir, time) -> {
            if (recursive && isDir) {
                receiveDir(line, path, time, preserve, bufferSize);
            } else {
                receiveFile(line, path, time, preserve, bufferSize);
            }
        });
    }

    protected void receive(ScpReceiveLineHandler handler) throws IOException {
        ScpIoUtils.receive(getSession(), in, out, log, this, handler);
    }

    public void receiveDir(String header, Path local, ScpTimestampCommandDetails time, boolean preserve, int bufferSize)
            throws IOException {
        Path path = Objects.requireNonNull(local, "No local path").normalize().toAbsolutePath();
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("receiveDir({})[{}] Receiving directory {} - preserve={}, time={}, buffer-size={}", this, header,
                    path, preserve, time, bufferSize);
        }

        ScpReceiveDirCommandDetails details = new ScpReceiveDirCommandDetails(header);
        String name = details.getName();
        long length = details.getLength();
        if (length != 0) {
            throw new IOException("Expected 0 length for directory=" + name + " but got " + length);
        }

        Session session = getSession();
        Set<PosixFilePermission> perms = details.getPermissions();
        Path file = opener.resolveIncomingFilePath(session, path, name, preserve, perms, time);

        ack();

        time = null;

        listener.startFolderEvent(session, FileOperation.RECEIVE, path, perms);
        try {
            for (;;) {
                header = readLine();
                if (debugEnabled) {
                    log.debug("receiveDir({})[{}] Received header: {}", this, file, header);
                }

                char cmdChar = header.charAt(0);
                if (cmdChar == ScpReceiveFileCommandDetails.COMMAND_NAME) {
                    receiveFile(header, file, time, preserve, bufferSize);
                    time = null;
                } else if (cmdChar == ScpReceiveDirCommandDetails.COMMAND_NAME) {
                    receiveDir(header, file, time, preserve, bufferSize);
                    time = null;
                } else if (cmdChar == ScpDirEndCommandDetails.COMMAND_NAME) {
                    ack();
                    break;
                } else if (cmdChar == ScpTimestampCommandDetails.COMMAND_NAME) {
                    time = ScpTimestampCommandDetails.parseTime(header);
                    ack();
                } else {
                    throw new IOException("Unexpected message: '" + header + "'");
                }
            }
        } catch (IOException | RuntimeException e) {
            listener.endFolderEvent(session, FileOperation.RECEIVE, path, perms, e);
            throw e;
        }
        listener.endFolderEvent(session, FileOperation.RECEIVE, path, perms, null);
    }

    public void receiveFile(String header, Path local, ScpTimestampCommandDetails time, boolean preserve, int bufferSize)
            throws IOException {
        Path path = Objects.requireNonNull(local, "No local path").normalize().toAbsolutePath();
        if (log.isDebugEnabled()) {
            log.debug("receiveFile({})[{}] Receiving file {} - preserve={}, time={}, buffer-size={}", this, header,
                    path, preserve, time, bufferSize);
        }

        ScpTargetStreamResolver targetStreamResolver = opener.createScpTargetStreamResolver(getSession(), path);
        receiveStream(header, targetStreamResolver, time, preserve, bufferSize);
    }

    public void receiveStream(
            String header, ScpTargetStreamResolver resolver, ScpTimestampCommandDetails time, boolean preserve,
            int bufferSize)
            throws IOException {
        if (bufferSize < MIN_RECEIVE_BUFFER_SIZE) {
            throw new IOException(
                    "receiveStream(" + resolver + ") buffer size (" + bufferSize + ") below minimum ("
                                  + MIN_RECEIVE_BUFFER_SIZE + ")");
        }

        ScpReceiveFileCommandDetails details = new ScpReceiveFileCommandDetails(header);
        long length = details.getLength();
        if (length < 0L) { // TODO consider throwing an exception...
            log.warn("receiveStream({})[{}] bad length in header: {}", this, resolver, header);
        }

        // if file size is less than buffer size allocate only expected file
        // size
        int bufSize;
        boolean debugEnabled = log.isDebugEnabled();
        if (length == 0L) {
            if (debugEnabled) {
                log.debug("receiveStream({})[{}] zero file size (perhaps special file) using copy buffer size={}", this,
                        resolver, MIN_RECEIVE_BUFFER_SIZE);
            }
            bufSize = MIN_RECEIVE_BUFFER_SIZE;
        } else {
            bufSize = (int) Math.min(length, bufferSize);
        }

        if (bufSize < 0) { // TODO consider throwing an exception
            log.warn("receiveStream({})[{}] bad buffer size ({}) using default ({})", this, resolver, bufSize,
                    MIN_RECEIVE_BUFFER_SIZE);
            bufSize = MIN_RECEIVE_BUFFER_SIZE;
        }

        Session session = getSession();
        String name = details.getName();
        Set<PosixFilePermission> perms = details.getPermissions();
        try (InputStream is = new LimitInputStream(this.in, length);
             OutputStream os = resolver.resolveTargetStream(session, name, length, perms,
                     IoUtils.EMPTY_OPEN_OPTIONS)) {
            ack();

            Path file = resolver.getEventListenerFilePath();
            listener.startFileEvent(session, FileOperation.RECEIVE, file, length, perms);
            try {
                IoUtils.copy(is, os, bufSize);
            } catch (IOException | RuntimeException e) {
                listener.endFileEvent(session, FileOperation.RECEIVE, file, length, perms, e);
                throw e;
            }
            listener.endFileEvent(session, FileOperation.RECEIVE, file, length, perms, null);
            resolver.closeTargetStream(session, name, length, perms, os);
        }

        resolver.postProcessReceivedData(name, preserve, perms, time);

        ack();

        int replyCode = readAck(false);
        if (debugEnabled) {
            log.debug("receiveStream({})[{}] ack reply code={}", this, resolver, replyCode);
        }
        validateAckReplyCode("receiveStream", resolver, replyCode, false);
    }

    public String readLine() throws IOException {
        return readLine(false);
    }

    public String readLine(boolean canEof) throws IOException {
        return ScpIoUtils.readLine(in, canEof);
    }

    public void send(Collection<String> paths, boolean recursive, boolean preserve, int bufferSize) throws IOException {
        int readyCode = readAck(false);
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("send({}) ready code={}", paths, readyCode);
        }
        validateOperationReadyCode("send", "Paths", readyCode, false);

        LinkOption[] options = IoUtils.getLinkOptions(true);
        for (String pattern : paths) {
            pattern = pattern.replace('/', File.separatorChar);

            int idx = pattern.indexOf('*'); // check if wildcard used
            if (idx >= 0) {
                String basedir = "";
                String fixedPart = pattern.substring(0, idx);
                int lastSep = fixedPart.lastIndexOf(File.separatorChar);
                if (lastSep >= 0) {
                    basedir = pattern.substring(0, lastSep);
                    pattern = pattern.substring(lastSep + 1);
                }

                Session session = getSession();
                Path basePath = resolveLocalPath(basedir);
                Iterable<Path> included = opener.getMatchingFilesToSend(session, basePath, pattern);
                for (Path file : included) {
                    if (opener.sendAsRegularFile(session, file, options)) {
                        sendFile(file, preserve, bufferSize);
                    } else if (opener.sendAsDirectory(session, file, options)) {
                        if (!recursive) {
                            if (debugEnabled) {
                                log.debug("send({}) {}: not a regular file", this, file);
                            }
                            String path = basePath.relativize(file).toString();
                            sendWarning(path.replace(File.separatorChar, '/') + " not a regular file");
                        } else {
                            sendDir(file, preserve, bufferSize);
                        }
                    } else {
                        if (debugEnabled) {
                            log.debug("send({}) {}: unknown file type", this, file);
                        }
                        String path = basePath.relativize(file).toString();
                        sendWarning(path.replace(File.separatorChar, '/') + " unknown file type");
                    }
                }
            } else {
                send(resolveLocalPath(pattern), recursive, preserve, bufferSize, options);
            }
        }
    }

    public void sendPaths(Collection<? extends Path> paths, boolean recursive, boolean preserve, int bufferSize)
            throws IOException {
        int readyCode = readAck(false);
        if (log.isDebugEnabled()) {
            log.debug("sendPaths({}) ready code={}", paths, readyCode);
        }
        validateOperationReadyCode("sendPaths", "Paths", readyCode, false);

        LinkOption[] options = IoUtils.getLinkOptions(true);
        for (Path file : paths) {
            send(file, recursive, preserve, bufferSize, options);
        }
    }

    protected void send(Path local, boolean recursive, boolean preserve, int bufferSize, LinkOption... options)
            throws IOException {
        Path localPath = Objects.requireNonNull(local, "No local path").normalize().toAbsolutePath();
        Session session = getSession();
        Path file = opener.resolveOutgoingFilePath(session, localPath, options);
        if (opener.sendAsRegularFile(session, file, options)) {
            sendFile(file, preserve, bufferSize);
        } else if (opener.sendAsDirectory(session, file, options)) {
            if (!recursive) {
                throw new IOException(file + " not a regular file");
            } else {
                sendDir(file, preserve, bufferSize);
            }
        } else {
            throw new IOException(file + ": unknown file type");
        }
    }

    public Path resolveLocalPath(String basedir, String subpath) throws IOException {
        if (GenericUtils.isEmpty(basedir)) {
            return resolveLocalPath(subpath);
        } else {
            return resolveLocalPath(basedir + File.separator + subpath);
        }
    }

    /**
     * @param  commandPath          The command path using the <U>local</U> file separator
     * @return                      The resolved absolute and normalized local {@link Path}
     * @throws IOException          If failed to resolve the path
     * @throws InvalidPathException If invalid local path value
     */
    public Path resolveLocalPath(String commandPath) throws IOException, InvalidPathException {
        Path p = opener.resolveLocalPath(getSession(), fileSystem, commandPath);
        if (log.isTraceEnabled()) {
            log.trace("resolveLocalPath({}) {}: {}", this, commandPath, p);
        }

        return p;
    }

    public void sendFile(Path local, boolean preserve, int bufferSize) throws IOException {
        Path path = Objects.requireNonNull(local, "No local path").normalize().toAbsolutePath();
        if (log.isDebugEnabled()) {
            log.debug("sendFile({})[preserve={},buffer-size={}] Sending file {}", this, preserve, bufferSize, path);
        }

        ScpSourceStreamResolver sourceStreamResolver = opener.createScpSourceStreamResolver(getSession(), path);
        sendStream(sourceStreamResolver, preserve, bufferSize);
    }

    public void sendStream(ScpSourceStreamResolver resolver, boolean preserve, int bufferSize) throws IOException {
        if (bufferSize < MIN_SEND_BUFFER_SIZE) {
            throw new IOException(
                    "sendStream(" + resolver + ") buffer size (" + bufferSize + ") below minimum ("
                                  + MIN_SEND_BUFFER_SIZE + ")");
        }

        long fileSize = resolver.getSize();
        // if file size is less than buffer size allocate only expected file
        // size
        int bufSize;
        boolean debugEnabled = log.isDebugEnabled();
        if (fileSize <= 0L) {
            if (debugEnabled) {
                log.debug("sendStream({})[{}] unknown file size ({}) perhaps special file - using copy buffer size={}",
                        this, resolver, fileSize, MIN_SEND_BUFFER_SIZE);
            }
            bufSize = MIN_SEND_BUFFER_SIZE;
        } else {
            bufSize = (int) Math.min(fileSize, bufferSize);
        }

        if (bufSize < 0) { // TODO consider throwing an exception
            log.warn("sendStream({})[{}] bad buffer size ({}) using default ({})", this, resolver, bufSize,
                    MIN_SEND_BUFFER_SIZE);
            bufSize = MIN_SEND_BUFFER_SIZE;
        }

        ScpTimestampCommandDetails time = resolver.getTimestamp();
        if (preserve && (time != null)) {
            int readyCode = ScpIoUtils.sendTimeCommand(in, out, time, log, this);
            String cmd = time.toHeader();
            if (debugEnabled) {
                log.debug("sendStream({})[{}] command='{}' ready code={}", this, resolver, cmd, readyCode);
            }

            validateAckReplyCode(cmd, resolver, readyCode, false);
        }

        Set<PosixFilePermission> perms = EnumSet.copyOf(resolver.getPermissions());
        String octalPerms = ((!preserve) || GenericUtils.isEmpty(perms))
                ? ScpReceiveFileCommandDetails.DEFAULT_FILE_OCTAL_PERMISSIONS
                : ScpPathCommandDetailsSupport.getOctalPermissions(perms);
        String fileName = resolver.getFileName();
        String cmd = ScpReceiveFileCommandDetails.COMMAND_NAME + octalPerms + " " + fileSize + " " + fileName;
        if (debugEnabled) {
            log.debug("sendStream({})[{}] send 'C' command: {}", this, resolver, cmd);
        }

        int readyCode = sendAcknowledgedCommand(cmd);
        if (debugEnabled) {
            log.debug("sendStream({})[{}] command='{}' ready code={}", this, resolver,
                    cmd.substring(0, cmd.length() - 1), readyCode);
        }
        validateAckReplyCode(cmd, resolver, readyCode, false);

        Session session = getSession();
        try (InputStream in = resolver.resolveSourceStream(session, fileSize, perms, IoUtils.EMPTY_OPEN_OPTIONS)) {
            Path path = resolver.getEventListenerFilePath();
            listener.startFileEvent(session, FileOperation.SEND, path, fileSize, perms);
            try {
                IoUtils.copy(in, out, bufSize);
            } catch (IOException | RuntimeException e) {
                listener.endFileEvent(session, FileOperation.SEND, path, fileSize, perms, e);
                throw e;
            }
            listener.endFileEvent(session, FileOperation.SEND, path, fileSize, perms, null);
            resolver.closeSourceStream(session, fileSize, perms, in);
        }
        ack();

        readyCode = readAck(false);
        if (debugEnabled) {
            log.debug("sendStream({})[{}] command='{}' reply code={}", this, resolver, cmd, readyCode);
        }
        validateAckReplyCode("sendStream", resolver, readyCode, false);
    }

    protected void validateOperationReadyCode(String command, Object location, int readyCode, boolean eofAllowed)
            throws IOException {
        validateCommandStatusCode(command, location, readyCode, eofAllowed);
    }

    protected void validateAckReplyCode(String command, Object location, int replyCode, boolean eofAllowed)
            throws IOException {
        validateCommandStatusCode(command, location, replyCode, eofAllowed);
    }

    protected void validateCommandStatusCode(String command, Object location, int statusCode, boolean eofAllowed)
            throws IOException {
        ScpIoUtils.validateCommandStatusCode(command, location, statusCode, eofAllowed);
    }

    public void sendDir(Path local, boolean preserve, int bufferSize) throws IOException {
        Path path = Objects.requireNonNull(local, "No local path").normalize().toAbsolutePath();
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("sendDir({}) Sending directory {} - preserve={}, buffer-size={}", this, path, preserve,
                    bufferSize);
        }

        LinkOption[] options = IoUtils.getLinkOptions(true);
        Session session = getSession();
        if (preserve) {
            BasicFileAttributes basic = opener.getLocalBasicFileAttributes(session, path, options);
            FileTime lastModified = basic.lastModifiedTime();
            FileTime lastAccess = basic.lastAccessTime();
            ScpTimestampCommandDetails time = new ScpTimestampCommandDetails(lastModified, lastAccess);
            String cmd = time.toHeader();
            if (debugEnabled) {
                log.debug("sendDir({})[{}] send last-modified={}, last-access={} command: {}", this, path, lastModified,
                        lastAccess, cmd);
            }

            int readyCode = sendAcknowledgedCommand(cmd);
            if (debugEnabled) {
                if (debugEnabled) {
                    log.debug("sendDir({})[{}] command='{}' ready code={}", this, path, cmd, readyCode);
                }
            }
            validateAckReplyCode(cmd, path, readyCode, false);
        }

        Set<PosixFilePermission> perms = opener.getLocalFilePermissions(session, path, options);
        String octalPerms = ((!preserve) || GenericUtils.isEmpty(perms))
                ? ScpReceiveDirCommandDetails.DEFAULT_DIR_OCTAL_PERMISSIONS
                : ScpPathCommandDetailsSupport.getOctalPermissions(perms);
        String cmd = ScpReceiveDirCommandDetails.COMMAND_NAME + octalPerms + " " + "0" + " "
                     + Objects.toString(path.getFileName(), null);
        if (debugEnabled) {
            log.debug("sendDir({})[{}] send 'D' command: {}", this, path, cmd);
        }

        int readyCode = sendAcknowledgedCommand(cmd);
        if (debugEnabled) {
            log.debug("sendDir({})[{}] command='{}' ready code={}", this, path, cmd, readyCode);
        }
        validateAckReplyCode(cmd, path, readyCode, false);

        try (DirectoryStream<Path> children = opener.getLocalFolderChildren(session, path)) {
            listener.startFolderEvent(session, FileOperation.SEND, path, perms);

            try {
                for (Path child : children) {
                    if (opener.sendAsRegularFile(session, child, options)) {
                        sendFile(child, preserve, bufferSize);
                    } else if (opener.sendAsDirectory(session, child, options)) {
                        sendDir(child, preserve, bufferSize);
                    }
                }
            } catch (IOException | RuntimeException e) {
                listener.endFolderEvent(session, FileOperation.SEND, path, perms, e);
                throw e;
            }

            listener.endFolderEvent(session, FileOperation.SEND, path, perms, null);
        }

        if (debugEnabled) {
            log.debug("sendDir({})[{}] send 'E' command", this, path);
        }

        readyCode = sendAcknowledgedCommand(ScpDirEndCommandDetails.HEADER);
        if (debugEnabled) {
            log.debug("sendDir({})[{}] 'E' command reply code=", this, path, readyCode);
        }
        validateAckReplyCode(ScpDirEndCommandDetails.HEADER, path, readyCode, false);
    }

    protected int sendAcknowledgedCommand(String cmd) throws IOException {
        return ScpIoUtils.sendAcknowledgedCommand(cmd, in, out, log);
    }

    protected void sendWarning(String message) throws IOException {
        sendResponseMessage(ScpIoUtils.WARNING, message);
    }

    protected void sendError(String message) throws IOException {
        sendResponseMessage(ScpIoUtils.ERROR, message);
    }

    protected void sendResponseMessage(int level, String message) throws IOException {
        ScpIoUtils.sendResponseMessage(out, level, message);
    }

    public void ack() throws IOException {
        ScpIoUtils.ack(out);
    }

    public int readAck(boolean canEof) throws IOException {
        return ScpIoUtils.readAck(in, canEof, log, this);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getSession() + "]";
    }
}
