/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
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
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.LinkOption;
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
import org.apache.sshd.common.util.DirectoryScanner;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.LimitInputStream;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpHelper extends AbstractLoggingBean {
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

    public static final int S_IRUSR =  0000400;
    public static final int S_IWUSR =  0000200;
    public static final int S_IXUSR =  0000100;
    public static final int S_IRGRP =  0000040;
    public static final int S_IWGRP =  0000020;
    public static final int S_IXGRP =  0000010;
    public static final int S_IROTH =  0000004;
    public static final int S_IWOTH =  0000002;
    public static final int S_IXOTH =  0000001;

    protected final FileSystem fileSystem;
    protected final InputStream in;
    protected final OutputStream out;
    protected final ScpTransferEventListener listener;

    public ScpHelper(InputStream in, OutputStream out, FileSystem fileSystem, ScpTransferEventListener eventListener) {
        this.in = in;
        this.out = out;
        this.fileSystem = fileSystem;
        this.listener = (eventListener == null) ? ScpTransferEventListener.EMPTY : eventListener;
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
                    public OutputStream resolveTargetStream(String name, long length, Set<PosixFilePermission> perms) throws IOException {
                        if (log.isDebugEnabled()) {
                            log.debug("resolveTargetStream(" + name + ")[" + perms + "][len=" + length + "] started local stream download");
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
                            log.debug("postProcessReceivedData(" + name + ")[" + perms + "][time=" + time + "] ended local stream download");
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

    public void receive(final Path path, final boolean recursive, boolean shouldBeDir, final boolean preserve, final int bufferSize) throws IOException {
        if (shouldBeDir) {
            LinkOption[] options = IoUtils.getLinkOptions(false);
            Boolean      status = IoUtils.checkFileExists(path, options);
            if (status == null) {
                throw new SshException("Target directory " + path + " is most like inaccessible");
            }
            if (!status.booleanValue()) {
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
                case 'C':
                    line = String.valueOf((char) c) + readLine();
                    log.debug("Received header: " + line);
                    break;
                case 'T':
                    line = String.valueOf((char) c) + readLine();
                    log.debug("Received header: " + line);
                    time = ScpTimestamp.parseTime(line);
                    ack();
                    continue;
                case 'E':
                    line = String.valueOf((char) c) + readLine();
                    log.debug("Received header: " + line);
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
    public void receiveDir(String header, Path path, ScpTimestamp time, boolean preserve, int bufferSize) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Receiving directory {}", path);
        }
        if (!header.startsWith("D")) {
            throw new IOException("Expected a D message but got '" + header + "'");
        }

        Set<PosixFilePermission> perms = parseOctalPerms(header.substring(1, 5));
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

        Path file=null;
        if (status.booleanValue() && Files.isDirectory(path, options)) {
            String localName = name.replace('/', File.separatorChar);
            file = path.resolve(localName);
        } else if (!status.booleanValue()) {
            Path parent = path.getParent();

            status = IoUtils.checkFileExists(parent, options);
            if (status == null) {
                throw new AccessDeniedException("Receive directory parent (" + parent + ") existence status cannot be determined for " + path);
            }
                
            if (status.booleanValue() && Files.isDirectory(parent, options)) { 
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
            for (; ; ) {
                header = readLine();
                if (log.isDebugEnabled()) {
                    log.debug("Received header: " + header);
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

    public void receiveFile(String header, Path path, ScpTimestamp time, boolean preserve, int bufferSize) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Receiving file {}", path);
        }

        receiveStream(header, new LocalFileScpTargetStreamResolver(path), time, preserve, bufferSize);
    }

    public void receiveStream(String header, ScpTargetStreamResolver resolver, ScpTimestamp time, boolean preserve, int bufferSize) throws IOException {
        if (!header.startsWith("C")) {
            throw new IOException("receiveStream(" + resolver + ") Expected a C message but got '" + header + "'");
        }

        if (bufferSize < MIN_RECEIVE_BUFFER_SIZE) {
            throw new IOException("receiveStream(" + resolver + ") buffer size (" + bufferSize + ") below minimum (" + MIN_RECEIVE_BUFFER_SIZE + ")");
        }

        Set<PosixFilePermission> perms = parseOctalPerms(header.substring(1, 5));
        final long length = Long.parseLong(header.substring(6, header.indexOf(' ', 6)));
        String name = header.substring(header.indexOf(' ', 6) + 1);
        if (length < 0L) { // TODO consider throwing an exception...
            log.warn("receiveStream(" + resolver + ") bad length in header: " + header);
        }

        // if file size is less than buffer size allocate only expected file size
        int bufSize;
        if (length == 0L) {
            if (log.isDebugEnabled()) {
                log.debug("receiveStream(" + resolver + ") zero file size (perhaps special file) using copy buffer size=" + MIN_RECEIVE_BUFFER_SIZE);
            }
            bufSize = MIN_RECEIVE_BUFFER_SIZE;
        } else {
            bufSize = (int) Math.min(length, bufferSize);
        }

        if (bufSize < 0) { // TODO consider throwing an exception
            log.warn("receiveFile(" + resolver + ") bad buffer size (" + bufSize + ") using default (" + MIN_RECEIVE_BUFFER_SIZE + ")");
            bufSize = MIN_RECEIVE_BUFFER_SIZE;
        }

        try (
                InputStream is = new LimitInputStream(this.in, length);
                OutputStream os = resolver.resolveTargetStream(name, length, perms)
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
        readAck(false);

    }

    protected void updateFileProperties(Path file, Set<PosixFilePermission> perms, ScpTimestamp time) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("updateFileProperties(" + file + ") permissions: " + perms);
        }
        IoUtils.setPermissions(file, perms);

        if (time != null) {
            BasicFileAttributeView view = Files.getFileAttributeView(file, BasicFileAttributeView.class);
            FileTime lastModified = FileTime.from(time.lastModifiedTime, TimeUnit.MILLISECONDS);
            FileTime lastAccess = FileTime.from(time.lastAccessTime, TimeUnit.MILLISECONDS);
            if (log.isTraceEnabled()) {
                log.trace("updateFileProperties(" + file + ") last-modified=" + lastModified + ", last-access=" + lastAccess);
            }
            view.setTimes(lastModified, lastAccess, null);
        }
    }

    public String readLine() throws IOException {
        return readLine(false);
    }

    public String readLine(boolean canEof) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (; ; ) {
            int c = in.read();
            if (c == '\n') {
                return baos.toString();
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

    public void send(Collection<String> paths, boolean recursive, boolean preserve, int bufferSize) throws IOException {
        readAck(false);
        
        LinkOption[]    options=IoUtils.getLinkOptions(false);
        for (String pattern : paths) {
            pattern = pattern.replace('/', File.separatorChar);

            int idx = pattern.indexOf('*');
            if (idx >= 0) {
                String basedir = "";
                int lastSep = pattern.substring(0, idx).lastIndexOf(File.separatorChar);
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
                            out.write(ScpHelper.WARNING);
                            out.write((path.toString().replace(File.separatorChar, '/') + " not a regular file\n").getBytes());
                        } else {
                            sendDir(file, preserve, bufferSize);
                        }
                    } else {
                        out.write(ScpHelper.WARNING);
                        out.write((path.toString().replace(File.separatorChar, '/') + " unknown file type\n").getBytes());
                    }
                }
            } else {
                String basedir = "";
                int lastSep = pattern.lastIndexOf(File.separatorChar);
                if (lastSep >= 0) {
                    basedir = pattern.substring(0, lastSep);
                    pattern = pattern.substring(lastSep + 1);
                }

                send(resolveLocalPath(basedir, pattern), recursive, preserve, bufferSize, options);
            }
        }
    }

    public void sendPaths(Collection<? extends Path> paths, boolean recursive, boolean preserve, int bufferSize) throws IOException {
        readAck(false);
        
        LinkOption[]    options=IoUtils.getLinkOptions(false);
        for (Path file : paths) {
            send(file, recursive, preserve, bufferSize, options);
        }
    }

    protected void send(Path file, boolean recursive, boolean preserve, int bufferSize, LinkOption ... options) throws IOException {
        Boolean status = IoUtils.checkFileExists(file, options);
        if (status == null) {
            throw new AccessDeniedException("Send file existence status cannot be determined: " + file);
        }
        if (!status.booleanValue()) {
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

    public Path resolveLocalPath(String basedir, String subpath) {
        if (GenericUtils.isEmpty(basedir)) {
            return resolveLocalPath(subpath);
        } else {
            return resolveLocalPath(basedir + File.separator + subpath);
        }
    }

    public Path resolveLocalPath(String path) {
        String localPath = (path == null) ? null : path.replace('/', File.separatorChar);
        return fileSystem.getPath(localPath);
    }

    public void sendFile(Path path, boolean preserve, int bufferSize) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Sending file {}", path);
        }

        sendStream(new LocalFileScpSourceStreamResolver(path), preserve, bufferSize);
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
                log.debug("sendStream(" + resolver + ") unknown file size (" + fileSize + ")  perhaps special file - using copy buffer size=" + MIN_SEND_BUFFER_SIZE);
            }
            bufSize = MIN_SEND_BUFFER_SIZE;
        } else {
            bufSize = (int) Math.min(fileSize, bufferSize);
        }

        if (bufSize < 0) { // TODO consider throwing an exception
            log.warn("sendStream(" + resolver + ") bad buffer size (" + bufSize + ") using default (" + MIN_SEND_BUFFER_SIZE + ")");
            bufSize = MIN_SEND_BUFFER_SIZE;
        }

        ScpTimestamp time = resolver.getTimestamp();
        if (preserve && (time != null)) {
            String cmd = new StringBuilder(Long.SIZE)
                    .append('T').append(TimeUnit.MILLISECONDS.toSeconds(time.lastModifiedTime)).append(' ').append('0')
                    .append(' ').append(TimeUnit.MILLISECONDS.toSeconds(time.lastAccessTime)).append(' ').append('0')
                    .append('\n')
                    .toString();
            out.write(cmd.getBytes());
            out.flush();
            readAck(false);
        }

        Set<PosixFilePermission> perms = EnumSet.copyOf(resolver.getPermissions());
        String octalPerms = preserve ? getOctalPerms(perms) : "0644";
        String fileName = resolver.getFileName();
        String cmd = new StringBuilder(octalPerms.length() + fileName.length() + Long.SIZE /* some extra delimiters */)
            .append('C').append(octalPerms)
            .append(' ').append(fileSize)
            .append(' ').append(fileName)
            .append('\n')
            .toString();
        out.write(cmd.getBytes());
        out.flush();
        readAck(false);

        try (InputStream in = resolver.resolveSourceStream()) {
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
        readAck(false);
    }

    public void sendDir(Path path, boolean preserve, int bufferSize) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Sending directory {}", path);
        }

        BasicFileAttributes basic = Files.getFileAttributeView(path, BasicFileAttributeView.class).readAttributes();
        if (preserve) {
            StringBuilder buf = new StringBuilder();
            buf.append("T");
            buf.append(basic.lastModifiedTime().to(TimeUnit.SECONDS));
            buf.append(" ");
            buf.append("0");
            buf.append(" ");
            buf.append(basic.lastAccessTime().to(TimeUnit.SECONDS));
            buf.append(" ");
            buf.append("0");
            buf.append("\n");
            out.write(buf.toString().getBytes());
            out.flush();
            readAck(false);
        }

        LinkOption[] options = IoUtils.getLinkOptions(false);
        Set<PosixFilePermission> perms = IoUtils.getPermissions(path, options);
        StringBuilder buf = new StringBuilder();
        buf.append("D");
        buf.append(preserve ? getOctalPerms(perms) : "0755");
        buf.append(" ");
        buf.append("0"); // length
        buf.append(" ");
        buf.append(path.getFileName().toString());
        buf.append("\n");
        out.write(buf.toString().getBytes());
        out.flush();
        readAck(false);

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

        out.write("E\n".getBytes());
        out.flush();
        readAck(false);
    }

    public static String getOctalPerms(Path path, LinkOption ... options) throws IOException {
        return getOctalPerms(IoUtils.getPermissions(path, options));
    }

    public static String getOctalPerms(Collection<PosixFilePermission> perms) {
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

        return String.format("%04o", Integer.valueOf(pf));
    }

    public static Set<PosixFilePermission> setOctalPerms(Path path, String str) throws IOException {
        Set<PosixFilePermission> perms = parseOctalPerms(str);
        IoUtils.setPermissions(path, perms);
        return perms;
    }

    public static Set<PosixFilePermission> parseOctalPerms(String str) {
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

    public void ack() throws IOException {
        out.write(0);
        out.flush();
    }

    public int readAck(boolean canEof) throws IOException {
        int c = in.read();
        switch (c) {
        case -1:
            if (!canEof) {
                throw new EOFException("readAck - EOF before ACK");
            }
            break;
        case OK:
            break;
        case WARNING:
            log.warn("Received warning: " + readLine());
            break;
        case ERROR:
            throw new IOException("Received nack: " + readLine());
        default:
            break;
        }
        return c;
    }
}
