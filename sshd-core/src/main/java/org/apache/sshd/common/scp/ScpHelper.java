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
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.SshException;
import org.apache.sshd.common.file.util.MockPath;
import org.apache.sshd.common.scp.ScpTransferEventListener.FileOperation;
import org.apache.sshd.common.scp.helpers.DefaultScpFileOpener;
import org.apache.sshd.common.scp.helpers.LocalFileScpSourceStreamResolver;
import org.apache.sshd.common.scp.helpers.LocalFileScpTargetStreamResolver;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.SelectorUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.DirectoryScanner;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.LimitInputStream;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
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

    protected final InputStream in;
    protected final OutputStream out;
    protected final FileSystem fileSystem;
    protected final ScpFileOpener opener;
    protected final ScpTransferEventListener listener;

    private final Session sessionInstance;

    public ScpHelper(Session session, InputStream in, OutputStream out,
            FileSystem fileSystem, ScpFileOpener opener, ScpTransferEventListener eventListener) {
        this.sessionInstance = ValidateUtils.checkNotNull(session, "No session");
        this.in = ValidateUtils.checkNotNull(in, "No input stream");
        this.out = ValidateUtils.checkNotNull(out, "No output stream");
        this.fileSystem = fileSystem;
        this.opener = (opener == null) ? DefaultScpFileOpener.INSTANCE : opener;
        this.listener = (eventListener == null) ? ScpTransferEventListener.EMPTY : eventListener;
    }

    @Override
    public Session getSession() {
        return sessionInstance;
    }

    public void receiveFileStream(final OutputStream local, final int bufferSize) throws IOException {
        receive(new ScpReceiveLineHandler() {
            @Override
            public void process(final String line, boolean isDir, ScpTimestamp timestamp) throws IOException {
                if (isDir) {
                    throw new StreamCorruptedException("Cannot download a directory into a file stream: " + line);
                }

                final Path path = new MockPath(line);
                receiveStream(line, new ScpTargetStreamResolver() {
                    @SuppressWarnings("synthetic-access")
                    @Override
                    public OutputStream resolveTargetStream(Session session, String name, long length,
                            Set<PosixFilePermission> perms, OpenOption... options) throws IOException {
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
                    @SuppressWarnings("synthetic-access")
                    public void postProcessReceivedData(String name, boolean preserve, Set<PosixFilePermission> perms, ScpTimestamp time) throws IOException {
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
            }
        });
    }

    public void receive(Path local, final boolean recursive, boolean shouldBeDir, final boolean preserve, final int bufferSize) throws IOException {
        final Path path = ValidateUtils.checkNotNull(local, "No local path").normalize().toAbsolutePath();
        if (shouldBeDir) {
            LinkOption[] options = IoUtils.getLinkOptions(false);
            Boolean status = IoUtils.checkFileExists(path, options);
            if (status == null) {
                throw new SshException("Target directory " + path + " is most like inaccessible");
            }
            if (!status) {
                throw new SshException("Target directory " + path + " does not exist");
            }
            if (!Files.isDirectory(path, options)) {
                throw new SshException("Target directory " + path + " is not a directory");
            }
        }

        receive(new ScpReceiveLineHandler() {
            @Override
            public void process(String line, boolean isDir, ScpTimestamp time) throws IOException {
                if (recursive && isDir) {
                    receiveDir(line, path, time, preserve, bufferSize);
                } else {
                    receiveFile(line, path, time, preserve, bufferSize);
                }
            }
        });
    }

    protected void receive(ScpReceiveLineHandler handler) throws IOException {
        ack();
        ScpTimestamp time = null;
        for (;;) {
            String line;
            boolean isDir = false;
            int c = readAck(true);
            switch (c) {
                case -1:
                    return;
                case 'D':
                    isDir = true;
                    line = String.valueOf((char) c) + readLine();
                    if (log.isDebugEnabled()) {
                        log.debug("receive({}) - Received 'D' header: {}", this, line);
                    }
                    break;
                case 'C':
                    line = String.valueOf((char) c) + readLine();
                    if (log.isDebugEnabled()) {
                        log.debug("receive({}) - Received 'C' header: {}", this, line);
                    }
                    break;
                case 'T':
                    line = String.valueOf((char) c) + readLine();
                    if (log.isDebugEnabled()) {
                        log.debug("receive({}) - Received 'T' header: {}", this, line);
                    }
                    time = ScpTimestamp.parseTime(line);
                    ack();
                    continue;
                case 'E':
                    line = String.valueOf((char) c) + readLine();
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
                handler.process(line, isDir, time);
            } finally {
                time = null;
            }
        }
    }

    public void receiveDir(String header, Path local, ScpTimestamp time, boolean preserve, int bufferSize) throws IOException {
        Path path = ValidateUtils.checkNotNull(local, "No local path").normalize().toAbsolutePath();
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
            throw new IOException("Expected 0 length for directory but got " + length);
        }

        LinkOption[] options = IoUtils.getLinkOptions(false);
        Boolean status = IoUtils.checkFileExists(path, options);
        if (status == null) {
            throw new AccessDeniedException("Receive directory existence status cannot be determined: " + path);
        }

        Path file = null;
        if (status && Files.isDirectory(path, options)) {
            String localName = name.replace('/', File.separatorChar);
            file = path.resolve(localName);
        } else if (!status) {
            Path parent = path.getParent();

            status = IoUtils.checkFileExists(parent, options);
            if (status == null) {
                throw new AccessDeniedException("Receive directory parent (" + parent + ") existence status cannot be determined for " + path);
            }

            if (status && Files.isDirectory(parent, options)) {
                file = path;
            }
        }

        if (file == null) {
            throw new IOException("Cannot write to " + path);
        }

        status = IoUtils.checkFileExists(file, options);
        if (status == null) {
            throw new AccessDeniedException("Receive directory file existence status cannot be determined: " + file);
        }

        if (!(status.booleanValue() && Files.isDirectory(file, options))) {
            Files.createDirectory(file);
        }

        if (preserve) {
            updateFileProperties(file, perms, time);
        }

        ack();

        time = null;
        try {
            listener.startFolderEvent(FileOperation.RECEIVE, path, perms);
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
            listener.endFolderEvent(FileOperation.RECEIVE, path, perms, e);
            throw e;
        }
    }

    public void receiveFile(String header, Path local, ScpTimestamp time, boolean preserve, int bufferSize) throws IOException {
        Path path = ValidateUtils.checkNotNull(local, "No local path").normalize().toAbsolutePath();
        if (log.isDebugEnabled()) {
            log.debug("receiveFile({})[{}] Receiving file {} - preserve={}, time={}, buffer-size={}",
                      this, header, path, preserve, time, bufferSize);
        }

        receiveStream(header, new LocalFileScpTargetStreamResolver(path, opener), time, preserve, bufferSize);
    }

    public void receiveStream(String header, ScpTargetStreamResolver resolver, ScpTimestamp time, boolean preserve, int bufferSize) throws IOException {
        if (!header.startsWith("C")) {
            throw new IOException("receiveStream(" + resolver + ") Expected a C message but got '" + header + "'");
        }

        if (bufferSize < MIN_RECEIVE_BUFFER_SIZE) {
            throw new IOException("receiveStream(" + resolver + ") buffer size (" + bufferSize + ") below minimum (" + MIN_RECEIVE_BUFFER_SIZE + ")");
        }

        Set<PosixFilePermission> perms = parseOctalPermissions(header.substring(1, 5));
        final long length = Long.parseLong(header.substring(6, header.indexOf(' ', 6)));
        String name = header.substring(header.indexOf(' ', 6) + 1);
        if (length < 0L) { // TODO consider throwing an exception...
            log.warn("receiveStream({})[{}] bad length in header: {}", this, resolver, header);
        }

        // if file size is less than buffer size allocate only expected file size
        int bufSize;
        if (length == 0L) {
            if (log.isDebugEnabled()) {
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
                OutputStream os = resolver.resolveTargetStream(getSession(), name, length, perms)
        ) {
            ack();

            Path file = resolver.getEventListenerFilePath();
            try {
                listener.startFileEvent(FileOperation.RECEIVE, file, length, perms);
                IoUtils.copy(is, os, bufSize);
                listener.endFileEvent(FileOperation.RECEIVE, file, length, perms, null);
            } catch (IOException | RuntimeException e) {
                listener.endFileEvent(FileOperation.RECEIVE, file, length, perms, e);
                throw e;
            }
        }

        resolver.postProcessReceivedData(name, preserve, perms, time);

        ack();

        int replyCode = readAck(false);
        if (log.isDebugEnabled()) {
            log.debug("receiveStream({})[{}] ack reply code={}", this, resolver, replyCode);
        }
        validateAckReplyCode("receiveStream", resolver, replyCode, false);
    }

    protected void updateFileProperties(Path file, Set<PosixFilePermission> perms, ScpTimestamp time) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("updateFileProperties({}) {} permissions={}, time={}", this, file, perms, time);
        }
        IoUtils.setPermissions(file, perms);

        if (time != null) {
            BasicFileAttributeView view = Files.getFileAttributeView(file, BasicFileAttributeView.class);
            FileTime lastModified = FileTime.from(time.getLastModifiedTime(), TimeUnit.MILLISECONDS);
            FileTime lastAccess = FileTime.from(time.getLastAccessTime(), TimeUnit.MILLISECONDS);
            if (log.isTraceEnabled()) {
                log.trace("updateFileProperties({}) {} last-modified={}, last-access={}", this, file, lastModified, lastAccess);
            }
            view.setTimes(lastModified, lastAccess, null);
        }
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
        if (log.isDebugEnabled()) {
            log.debug("send({}) ready code={}", paths, readyCode);
        }
        validateOperationReadyCode("send", "Paths", readyCode, false);

        LinkOption[] options = IoUtils.getLinkOptions(false);
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

                String[] included = new DirectoryScanner(basedir, pattern).scan();
                for (String path : included) {
                    Path file = resolveLocalPath(basedir, path);
                    if (Files.isRegularFile(file, options)) {
                        sendFile(file, preserve, bufferSize);
                    } else if (Files.isDirectory(file, options)) {
                        if (!recursive) {
                            if (log.isDebugEnabled()) {
                                log.debug("send({}) {}: not a regular file", this, path);
                            }
                            sendWarning(path.replace(File.separatorChar, '/') + " not a regular file");
                        } else {
                            sendDir(file, preserve, bufferSize);
                        }
                    } else {
                        if (log.isDebugEnabled()) {
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

        LinkOption[] options = IoUtils.getLinkOptions(false);
        for (Path file : paths) {
            send(file, recursive, preserve, bufferSize, options);
        }
    }

    protected void send(Path local, boolean recursive, boolean preserve, int bufferSize, LinkOption... options) throws IOException {
        Path file = ValidateUtils.checkNotNull(local, "No local path").normalize().toAbsolutePath();
        Boolean status = IoUtils.checkFileExists(file, options);
        if (status == null) {
            throw new AccessDeniedException("Send file existence status cannot be determined: " + file);
        }
        if (!status) {
            throw new IOException(file + ": no such file or directory");
        }

        if (Files.isRegularFile(file, options)) {
            sendFile(file, preserve, bufferSize);
        } else if (Files.isDirectory(file, options)) {
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
     * @return The resolved absolute and normalized local path {@link Path}
     * @throws IOException If failed to resolve the path
     * @throws InvalidPathException If invalid local path value
     */
    public Path resolveLocalPath(String commandPath) throws IOException, InvalidPathException {
        String path = SelectorUtils.translateToLocalFileSystemPath(commandPath, File.separatorChar, fileSystem);
        Path lcl = fileSystem.getPath(path);
        Path abs = lcl.isAbsolute() ? lcl : lcl.toAbsolutePath();
        Path p = abs.normalize();
        if (log.isTraceEnabled()) {
            log.trace("resolveLocalPath({}) {}: {}", this, commandPath, p);
        }

        return p;
    }

    public void sendFile(Path local, boolean preserve, int bufferSize) throws IOException {
        Path path = ValidateUtils.checkNotNull(local, "No local path").normalize().toAbsolutePath();
        if (log.isDebugEnabled()) {
            log.debug("sendFile({})[preserve={},buffer-size={}] Sending file {}", this, preserve, bufferSize, path);
        }

        sendStream(new LocalFileScpSourceStreamResolver(path, opener), preserve, bufferSize);
    }

    public void sendStream(ScpSourceStreamResolver resolver, boolean preserve, int bufferSize) throws IOException {
        if (bufferSize < MIN_SEND_BUFFER_SIZE) {
            throw new IOException("sendStream(" + resolver + ") buffer size (" + bufferSize + ") below minimum (" + MIN_SEND_BUFFER_SIZE + ")");
        }

        long fileSize = resolver.getSize();
        // if file size is less than buffer size allocate only expected file size
        int bufSize;
        if (fileSize <= 0L) {
            if (log.isDebugEnabled()) {
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
            if (log.isDebugEnabled()) {
                log.debug("sendStream({})[{}] send timestamp={} command: {}", this, resolver, time, cmd);
            }
            out.write(cmd.getBytes(StandardCharsets.UTF_8));
            out.write('\n');
            out.flush();

            int readyCode = readAck(false);
            if (log.isDebugEnabled()) {
                log.debug("sendStream({})[{}] command='{}' ready code={}", this, resolver, cmd, readyCode);
            }
            validateAckReplyCode(cmd, resolver, readyCode, false);
        }

        Set<PosixFilePermission> perms = EnumSet.copyOf(resolver.getPermissions());
        String octalPerms = preserve ? getOctalPermissions(perms) : "0644";
        String fileName = resolver.getFileName();
        String cmd = "C" + octalPerms + " " + fileSize + " " + fileName;
        if (log.isDebugEnabled()) {
            log.debug("sendStream({})[{}] send 'C' command: {}", this, resolver, cmd);
        }
        out.write(cmd.getBytes(StandardCharsets.UTF_8));
        out.write('\n');
        out.flush();

        int readyCode = readAck(false);
        if (log.isDebugEnabled()) {
            log.debug("sendStream({})[{}] command='{}' ready code={}",
                      this, resolver, cmd.substring(0, cmd.length() - 1), readyCode);
        }
        validateAckReplyCode(cmd, resolver, readyCode, false);

        try (InputStream in = resolver.resolveSourceStream(getSession())) {
            Path path = resolver.getEventListenerFilePath();
            try {
                listener.startFileEvent(FileOperation.SEND, path, fileSize, perms);
                IoUtils.copy(in, out, bufSize);
                listener.endFileEvent(FileOperation.SEND, path, fileSize, perms, null);
            } catch (IOException | RuntimeException e) {
                listener.endFileEvent(FileOperation.SEND, path, fileSize, perms, e);
                throw e;
            }
        }
        ack();

        readyCode = readAck(false);
        if (log.isDebugEnabled()) {
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
                throw new ScpException("Bad reply code (" + statusCode + ") for command='" + command + "' on " + location, Integer.valueOf(statusCode));
        }
    }

    public void sendDir(Path local, boolean preserve, int bufferSize) throws IOException {
        Path path = ValidateUtils.checkNotNull(local, "No local path").normalize().toAbsolutePath();
        if (log.isDebugEnabled()) {
            log.debug("sendDir({}) Sending directory {} - preserve={}, buffer-size={}",
                      this, path, preserve, bufferSize);
        }

        BasicFileAttributes basic = Files.getFileAttributeView(path, BasicFileAttributeView.class).readAttributes();
        if (preserve) {
            FileTime lastModified = basic.lastModifiedTime();
            FileTime lastAccess = basic.lastAccessTime();
            String cmd = "T" + lastModified.to(TimeUnit.SECONDS) + " "
                    + "0" + " " + lastAccess.to(TimeUnit.SECONDS) + " "
                    + "0";
            if (log.isDebugEnabled()) {
                log.debug("sendDir({})[{}] send last-modified={}, last-access={} command: {}",
                          this, path, lastModified,  lastAccess, cmd);
            }

            out.write(cmd.getBytes(StandardCharsets.UTF_8));
            out.write('\n');
            out.flush();

            int readyCode = readAck(false);
            if (log.isDebugEnabled()) {
                if (log.isDebugEnabled()) {
                    log.debug("sendDir({})[{}] command='{}' ready code={}", this, path, cmd, readyCode);
                }
            }
            validateAckReplyCode(cmd, path, readyCode, false);
        }

        LinkOption[] options = IoUtils.getLinkOptions(false);
        Set<PosixFilePermission> perms = IoUtils.getPermissions(path, options);
        String cmd = "D" + (preserve ? getOctalPermissions(perms) : "0755") + " "
                + "0" + " " + path.getFileName().toString();
        if (log.isDebugEnabled()) {
            log.debug("sendDir({})[{}] send 'D' command: {}", this, path, cmd);
        }
        out.write(cmd.getBytes(StandardCharsets.UTF_8));
        out.write('\n');
        out.flush();

        int readyCode = readAck(false);
        if (log.isDebugEnabled()) {
            log.debug("sendDir({})[{}] command='{}' ready code={}",
                      this, path, cmd.substring(0, cmd.length() - 1), readyCode);
        }
        validateAckReplyCode(cmd, path, readyCode, false);

        try (DirectoryStream<Path> children = Files.newDirectoryStream(path)) {
            listener.startFolderEvent(FileOperation.SEND, path, perms);

            try {
                for (Path child : children) {
                    if (Files.isRegularFile(child, options)) {
                        sendFile(child, preserve, bufferSize);
                    } else if (Files.isDirectory(child, options)) {
                        sendDir(child, preserve, bufferSize);
                    }
                }

                listener.endFolderEvent(FileOperation.SEND, path, perms, null);
            } catch (IOException | RuntimeException e) {
                listener.endFolderEvent(FileOperation.SEND, path, perms, e);
                throw e;
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("sendDir({})[{}] send 'E' command", this, path);
        }
        out.write("E\n".getBytes(StandardCharsets.UTF_8));
        out.flush();


        readyCode = readAck(false);
        if (log.isDebugEnabled()) {
            log.debug("sendDir({})[{}] 'E' command reply code=", this, path, readyCode);
        }
        validateAckReplyCode("E", path, readyCode, false);
    }

    public static String getOctalPermissions(Path path, LinkOption... options) throws IOException {
        return getOctalPermissions(IoUtils.getPermissions(path, options));
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

    public static Set<PosixFilePermission> setOctalPermissions(Path path, String str) throws IOException {
        Set<PosixFilePermission> perms = parseOctalPermissions(str);
        IoUtils.setPermissions(path, perms);
        return perms;
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

        switch (exitStatus.intValue()) {
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
                throw new ScpException("Received nack: " + line, Integer.valueOf(c));
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
