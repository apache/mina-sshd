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
package org.apache.sshd.common.scp;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.nio.charset.StandardCharsets;
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
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.file.util.MockPath;
import org.apache.sshd.common.scp.ScpTransferEventListener.FileOperation;
import org.apache.sshd.common.scp.helpers.DefaultScpFileOpener;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.LimitInputStream;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@SuppressWarnings("PMD.AvoidUsingOctalValues")
public class ScpHelper extends AbstractLoggingBean implements SessionHolder<Session> {
    /**
     * Command prefix used to identify SCP commands
     */
    public static final String SCP_COMMAND_PREFIX = "scp";

    public static final int OK = 0;
    public static final int WARNING = 1;
    public static final int ERROR = 2;

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

    public static final int S_IRUSR = 0000400;
    public static final int S_IWUSR = 0000200;
    public static final int S_IXUSR = 0000100;
    public static final int S_IRGRP = 0000040;
    public static final int S_IWGRP = 0000020;
    public static final int S_IXGRP = 0000010;
    public static final int S_IROTH = 0000004;
    public static final int S_IWOTH = 0000002;
    public static final int S_IXOTH = 0000001;

    public static final String DEFAULT_DIR_OCTAL_PERMISSIONS = "0755";
    public static final String DEFAULT_FILE_OCTAL_PERMISSIONS = "0644";

    protected final InputStream in;
    protected final OutputStream out;
    protected final FileSystem fileSystem;
    protected final ScpFileOpener opener;
    protected final ScpTransferEventListener listener;

    private final Session sessionInstance;

    public ScpHelper(Session session, InputStream in, OutputStream out,
            FileSystem fileSystem, ScpFileOpener opener, ScpTransferEventListener eventListener) {
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
                @SuppressWarnings("synthetic-access")   // see https://bugs.eclipse.org/bugs/show_bug.cgi?id=537593
                public OutputStream resolveTargetStream(
                        Session session, String name, long length, Set<PosixFilePermission> perms, OpenOption... options)
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
                @SuppressWarnings("synthetic-access")   // see https://bugs.eclipse.org/bugs/show_bug.cgi?id=537593
                public void postProcessReceivedData(
                        String name, boolean preserve, Set<PosixFilePermission> perms, ScpTimestamp time)
                            throws IOException {
                    if (log.isDebugEnabled()) {
                        log.debug("postProcessReceivedData({}) name={}, perms={}, preserve={} time={}",
                              ScpHelper.this, name, perms, preserve, time);
                    }
                }

                @Override
                public String toString() {
                    return line;
                }
            }, timestamp, false, bufferSize);
        });
    }

    public void receive(Path local, boolean recursive, boolean shouldBeDir, boolean preserve, int bufferSize) throws IOException {
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
        ack();
        ScpTimestamp time = null;
        for (Session session = getSession();;) {
            String line;
            boolean isDir = false;
            int c = readAck(true);
            switch (c) {
                case -1:
                    return;
                case 'D':
                    line = readLine();
                    line = Character.toString((char) c) + line;
                    isDir = true;
                    if (log.isDebugEnabled()) {
                        log.debug("receive({}) - Received 'D' header: {}", this, line);
                    }
                    break;
                case 'C':
                    line = readLine();
                    line = Character.toString((char) c) + line;
                    if (log.isDebugEnabled()) {
                        log.debug("receive({}) - Received 'C' header: {}", this, line);
                    }
                    break;
                case 'T':
                    line = readLine();
                    line = Character.toString((char) c) + line;
                    if (log.isDebugEnabled()) {
                        log.debug("receive({}) - Received 'T' header: {}", this, line);
                    }
                    time = ScpTimestamp.parseTime(line);
                    ack();
                    continue;
                case 'E':
                    line = readLine();
                    line = Character.toString((char) c) + line;
                    if (log.isDebugEnabled()) {
                        log.debug("receive({}) - Received 'E' header: {}", this, line);
                    }
                    ack();
                    return;
                default:
                    //a real ack that has been acted upon already
                    continue;
            }

            try {
                handler.process(session, line, isDir, time);
            } finally {
                time = null;
            }
        }
    }

    public void receiveDir(String header, Path local, ScpTimestamp time, boolean preserve, int bufferSize) throws IOException {
        Path path = Objects.requireNonNull(local, "No local path").normalize().toAbsolutePath();
        if (log.isDebugEnabled()) {
            log.debug("receiveDir({})[{}] Receiving directory {} - preserve={}, time={}, buffer-size={}",
                      this, header, path, preserve, time, bufferSize);
        }
        if (!header.startsWith("D")) {
            throw new IOException("Expected a 'D; message but got '" + header + "'");
        }

        Set<PosixFilePermission> perms = parseOctalPermissions(header.substring(1, 5));
        int length = Integer.parseInt(header.substring(6, header.indexOf(' ', 6)));
        String name = header.substring(header.indexOf(' ', 6) + 1);
        if (length != 0) {
            throw new IOException("Expected 0 length for directory=" + name + " but got " + length);
        }

        Session session = getSession();
        Path file = opener.resolveIncomingFilePath(session, path, name, preserve, perms, time);

        ack();

        time = null;

        listener.startFolderEvent(session, FileOperation.RECEIVE, path, perms);
        try {
            for (;;) {
                header = readLine();
                if (log.isDebugEnabled()) {
                    log.debug("receiveDir({})[{}] Received header: {}", this, file, header);
                }
                if (header.startsWith("C")) {
                    receiveFile(header, file, time, preserve, bufferSize);
                    time = null;
                } else if (header.startsWith("D")) {
                    receiveDir(header, file, time, preserve, bufferSize);
                    time = null;
                } else if (header.equals("E")) {
                    ack();
                    break;
                } else if (header.startsWith("T")) {
                    time = ScpTimestamp.parseTime(header);
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

    public void receiveFile(String header, Path local, ScpTimestamp time, boolean preserve, int bufferSize) throws IOException {
        Path path = Objects.requireNonNull(local, "No local path").normalize().toAbsolutePath();
        if (log.isDebugEnabled()) {
            log.debug("receiveFile({})[{}] Receiving file {} - preserve={}, time={}, buffer-size={}",
                      this, header, path, preserve, time, bufferSize);
        }

        ScpTargetStreamResolver targetStreamResolver = opener.createScpTargetStreamResolver(getSession(), path);
        receiveStream(header, targetStreamResolver, time, preserve, bufferSize);
    }

    public void receiveStream(String header, ScpTargetStreamResolver resolver, ScpTimestamp time, boolean preserve, int bufferSize) throws IOException {
        if (!header.startsWith("C")) {
            throw new IOException("receiveStream(" + resolver + ") Expected a C message but got '" + header + "'");
        }

        if (bufferSize < MIN_RECEIVE_BUFFER_SIZE) {
            throw new IOException("receiveStream(" + resolver + ") buffer size (" + bufferSize + ") below minimum (" + MIN_RECEIVE_BUFFER_SIZE + ")");
        }

        Set<PosixFilePermission> perms = parseOctalPermissions(header.substring(1, 5));
        long length = Long.parseLong(header.substring(6, header.indexOf(' ', 6)));
        String name = header.substring(header.indexOf(' ', 6) + 1);
        if (length < 0L) { // TODO consider throwing an exception...
            log.warn("receiveStream({})[{}] bad length in header: {}", this, resolver, header);
        }

        // if file size is less than buffer size allocate only expected file size
        int bufSize;
        boolean debugEnabled = log.isDebugEnabled();
        if (length == 0L) {
            if (debugEnabled) {
                log.debug("receiveStream({})[{}] zero file size (perhaps special file) using copy buffer size={}",
                          this, resolver, MIN_RECEIVE_BUFFER_SIZE);
            }
            bufSize = MIN_RECEIVE_BUFFER_SIZE;
        } else {
            bufSize = (int) Math.min(length, bufferSize);
        }

        if (bufSize < 0) { // TODO consider throwing an exception
            log.warn("receiveStream({})[{}] bad buffer size ({}) using default ({})",
                     this, resolver, bufSize, MIN_RECEIVE_BUFFER_SIZE);
            bufSize = MIN_RECEIVE_BUFFER_SIZE;
        }

        try (
                InputStream is = new LimitInputStream(this.in, length);
                OutputStream os = resolver.resolveTargetStream(
                    getSession(), name, length, perms, IoUtils.EMPTY_OPEN_OPTIONS)
        ) {
            ack();

            Path file = resolver.getEventListenerFilePath();
            Session session = getSession();
            listener.startFileEvent(session, FileOperation.RECEIVE, file, length, perms);
            try {
                IoUtils.copy(is, os, bufSize);
            } catch (IOException | RuntimeException e) {
                listener.endFileEvent(session, FileOperation.RECEIVE, file, length, perms, e);
                throw e;
            }
            listener.endFileEvent(session, FileOperation.RECEIVE, file, length, perms, null);
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
                Iterable<String> included = opener.getMatchingFilesToSend(session, basedir, pattern);
                for (String path : included) {
                    Path file = resolveLocalPath(basedir, path);
                    if (opener.sendAsRegularFile(session, file, options)) {
                        sendFile(file, preserve, bufferSize);
                    } else if (opener.sendAsDirectory(session, file, options)) {
                        if (!recursive) {
                            if (debugEnabled) {
                                log.debug("send({}) {}: not a regular file", this, path);
                            }
                            sendWarning(path.replace(File.separatorChar, '/') + " not a regular file");
                        } else {
                            sendDir(file, preserve, bufferSize);
                        }
                    } else {
                        if (debugEnabled) {
                            log.debug("send({}) {}: unknown file type", this, path);
                        }
                        sendWarning(path.replace(File.separatorChar, '/') + " unknown file type");
                    }
                }
            } else {
                send(resolveLocalPath(pattern), recursive, preserve, bufferSize, options);
            }
        }
    }

    public void sendPaths(Collection<? extends Path> paths, boolean recursive, boolean preserve, int bufferSize) throws IOException {
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

    protected void send(Path local, boolean recursive, boolean preserve, int bufferSize, LinkOption... options) throws IOException {
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
     * @param commandPath The command path using the <U>local</U> file separator
     * @return The resolved absolute and normalized local {@link Path}
     * @throws IOException If failed to resolve the path
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
            throw new IOException("sendStream(" + resolver + ") buffer size (" + bufferSize + ") below minimum (" + MIN_SEND_BUFFER_SIZE + ")");
        }

        long fileSize = resolver.getSize();
        // if file size is less than buffer size allocate only expected file size
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
            log.warn("sendStream({})[{}] bad buffer size ({}) using default ({})",
                     this, resolver, bufSize, MIN_SEND_BUFFER_SIZE);
            bufSize = MIN_SEND_BUFFER_SIZE;
        }

        ScpTimestamp time = resolver.getTimestamp();
        if (preserve && (time != null)) {
            String cmd = "T" + TimeUnit.MILLISECONDS.toSeconds(time.getLastModifiedTime())
                    + " " + "0" + " " + TimeUnit.MILLISECONDS.toSeconds(time.getLastAccessTime())
                    + " " + "0";
            if (debugEnabled) {
                log.debug("sendStream({})[{}] send timestamp={} command: {}", this, resolver, time, cmd);
            }
            out.write(cmd.getBytes(StandardCharsets.UTF_8));
            out.write('\n');
            out.flush();

            int readyCode = readAck(false);
            if (debugEnabled) {
                log.debug("sendStream({})[{}] command='{}' ready code={}", this, resolver, cmd, readyCode);
            }
            validateAckReplyCode(cmd, resolver, readyCode, false);
        }

        Set<PosixFilePermission> perms = EnumSet.copyOf(resolver.getPermissions());
        String octalPerms = ((!preserve) || GenericUtils.isEmpty(perms)) ? DEFAULT_FILE_OCTAL_PERMISSIONS : getOctalPermissions(perms);
        String fileName = resolver.getFileName();
        String cmd = "C" + octalPerms + " " + fileSize + " " + fileName;
        if (debugEnabled) {
            log.debug("sendStream({})[{}] send 'C' command: {}", this, resolver, cmd);
        }
        out.write(cmd.getBytes(StandardCharsets.UTF_8));
        out.write('\n');
        out.flush();

        int readyCode = readAck(false);
        if (debugEnabled) {
            log.debug("sendStream({})[{}] command='{}' ready code={}",
                      this, resolver, cmd.substring(0, cmd.length() - 1), readyCode);
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
        }
        ack();

        readyCode = readAck(false);
        if (debugEnabled) {
            log.debug("sendStream({})[{}] command='{}' reply code={}", this, resolver, cmd, readyCode);
        }
        validateAckReplyCode("sendStream", resolver, readyCode, false);
    }

    protected void validateOperationReadyCode(String command, Object location, int readyCode, boolean eofAllowed) throws IOException {
        validateCommandStatusCode(command, location, readyCode, eofAllowed);
    }

    protected void validateAckReplyCode(String command, Object location, int replyCode, boolean eofAllowed) throws IOException {
        validateCommandStatusCode(command, location, replyCode, eofAllowed);
    }

    protected void validateCommandStatusCode(String command, Object location, int statusCode, boolean eofAllowed) throws IOException {
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
                throw new ScpException("Bad reply code (" + statusCode + ") for command='" + command + "' on " + location, statusCode);
        }
    }

    public void sendDir(Path local, boolean preserve, int bufferSize) throws IOException {
        Path path = Objects.requireNonNull(local, "No local path").normalize().toAbsolutePath();
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("sendDir({}) Sending directory {} - preserve={}, buffer-size={}",
                      this, path, preserve, bufferSize);
        }

        LinkOption[] options = IoUtils.getLinkOptions(true);
        Session session = getSession();
        if (preserve) {
            BasicFileAttributes basic = opener.getLocalBasicFileAttributes(session, path, options);
            FileTime lastModified = basic.lastModifiedTime();
            FileTime lastAccess = basic.lastAccessTime();
            String cmd = "T" + lastModified.to(TimeUnit.SECONDS) + " "
                    + "0" + " " + lastAccess.to(TimeUnit.SECONDS) + " "
                    + "0";
            if (debugEnabled) {
                log.debug("sendDir({})[{}] send last-modified={}, last-access={} command: {}",
                          this, path, lastModified,  lastAccess, cmd);
            }

            out.write(cmd.getBytes(StandardCharsets.UTF_8));
            out.write('\n');
            out.flush();

            int readyCode = readAck(false);
            if (debugEnabled) {
                if (debugEnabled) {
                    log.debug("sendDir({})[{}] command='{}' ready code={}", this, path, cmd, readyCode);
                }
            }
            validateAckReplyCode(cmd, path, readyCode, false);
        }

        Set<PosixFilePermission> perms = opener.getLocalFilePermissions(session, path, options);
        String octalPerms = ((!preserve) || GenericUtils.isEmpty(perms)) ? DEFAULT_DIR_OCTAL_PERMISSIONS : getOctalPermissions(perms);
        String cmd = "D" + octalPerms + " " + "0" + " " + Objects.toString(path.getFileName(), null);
        if (debugEnabled) {
            log.debug("sendDir({})[{}] send 'D' command: {}", this, path, cmd);
        }
        out.write(cmd.getBytes(StandardCharsets.UTF_8));
        out.write('\n');
        out.flush();

        int readyCode = readAck(false);
        if (debugEnabled) {
            log.debug("sendDir({})[{}] command='{}' ready code={}",
                      this, path, cmd.substring(0, cmd.length() - 1), readyCode);
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
        out.write("E\n".getBytes(StandardCharsets.UTF_8));
        out.flush();

        readyCode = readAck(false);
        if (debugEnabled) {
            log.debug("sendDir({})[{}] 'E' command reply code=", this, path, readyCode);
        }
        validateAckReplyCode("E", path, readyCode, false);
    }

    public static String getOctalPermissions(Collection<PosixFilePermission> perms) {
        int pf = 0;

        for (PosixFilePermission p : perms) {
            switch (p) {
                case OWNER_READ:
                    pf |= S_IRUSR;
                    break;
                case OWNER_WRITE:
                    pf |= S_IWUSR;
                    break;
                case OWNER_EXECUTE:
                    pf |= S_IXUSR;
                    break;
                case GROUP_READ:
                    pf |= S_IRGRP;
                    break;
                case GROUP_WRITE:
                    pf |= S_IWGRP;
                    break;
                case GROUP_EXECUTE:
                    pf |= S_IXGRP;
                    break;
                case OTHERS_READ:
                    pf |= S_IROTH;
                    break;
                case OTHERS_WRITE:
                    pf |= S_IWOTH;
                    break;
                case OTHERS_EXECUTE:
                    pf |= S_IXOTH;
                    break;
                default:    // ignored
            }
        }

        return String.format("%04o", pf);
    }

    public static Set<PosixFilePermission> parseOctalPermissions(String str) {
        int perms = Integer.parseInt(str, 8);
        Set<PosixFilePermission> p = EnumSet.noneOf(PosixFilePermission.class);
        if ((perms & S_IRUSR) != 0) {
            p.add(PosixFilePermission.OWNER_READ);
        }
        if ((perms & S_IWUSR) != 0) {
            p.add(PosixFilePermission.OWNER_WRITE);
        }
        if ((perms & S_IXUSR) != 0) {
            p.add(PosixFilePermission.OWNER_EXECUTE);
        }
        if ((perms & S_IRGRP) != 0) {
            p.add(PosixFilePermission.GROUP_READ);
        }
        if ((perms & S_IWGRP) != 0) {
            p.add(PosixFilePermission.GROUP_WRITE);
        }
        if ((perms & S_IXGRP) != 0) {
            p.add(PosixFilePermission.GROUP_EXECUTE);
        }
        if ((perms & S_IROTH) != 0) {
            p.add(PosixFilePermission.OTHERS_READ);
        }
        if ((perms & S_IWOTH) != 0) {
            p.add(PosixFilePermission.OTHERS_WRITE);
        }
        if ((perms & S_IXOTH) != 0) {
            p.add(PosixFilePermission.OTHERS_EXECUTE);
        }

        return p;
    }

    protected void sendWarning(String message) throws IOException {
        sendResponseMessage(WARNING, message);
    }

    protected void sendError(String message) throws IOException {
        sendResponseMessage(ERROR, message);
    }

    protected void sendResponseMessage(int level, String message) throws IOException {
        sendResponseMessage(out, level, message);
    }

    public static <O extends OutputStream> O sendWarning(O out, String message) throws IOException {
        return sendResponseMessage(out, WARNING, message);
    }

    public static <O extends OutputStream> O sendError(O out, String message) throws IOException {
        return sendResponseMessage(out, ERROR, message);
    }

    public static <O extends OutputStream> O sendResponseMessage(O out, int level, String message) throws IOException {
        out.write(level);
        out.write(message.getBytes(StandardCharsets.UTF_8));
        out.write('\n');
        out.flush();
        return out;
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

    public void ack() throws IOException {
        out.write(0);
        out.flush();
    }

    public int readAck(boolean canEof) throws IOException {
        int c = in.read();
        switch (c) {
            case -1:
                if (log.isDebugEnabled()) {
                    log.debug("readAck({})[EOF={}] received EOF", this, canEof);
                }
                if (!canEof) {
                    throw new EOFException("readAck - EOF before ACK");
                }
                break;
            case OK:
                if (log.isDebugEnabled()) {
                    log.debug("readAck({})[EOF={}] read OK", this, canEof);
                }
                break;
            case WARNING: {
                if (log.isDebugEnabled()) {
                    log.debug("readAck({})[EOF={}] read warning message", this, canEof);
                }

                String line = readLine();
                log.warn("readAck({})[EOF={}] - Received warning: {}", this, canEof, line);
                break;
            }
            case ERROR: {
                if (log.isDebugEnabled()) {
                    log.debug("readAck({})[EOF={}] read error message", this, canEof);
                }
                String line = readLine();
                if (log.isDebugEnabled()) {
                    log.debug("readAck({})[EOF={}] received error: {}", this, canEof, line);
                }
                throw new ScpException("Received nack: " + line, c);
            }
            default:
                break;
        }
        return c;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getSession() + "]";
    }
}
