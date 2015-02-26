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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.sshd.common.SshException;
import org.apache.sshd.common.file.FileSystemView;
import org.apache.sshd.common.file.SshFile;
import org.apache.sshd.common.util.DirectoryScanner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpHelper {

    protected static final Logger log = LoggerFactory.getLogger(ScpHelper.class);

    public static final int OK = 0;
    public static final int WARNING = 1;
    public static final int ERROR = 2;

    /**
     * Default size (in bytes) of send / receive buffer size
     */
    public static final int DEFAULT_COPY_BUFFER_SIZE = 8192;
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

    protected final FileSystemView root;
    protected final InputStream in;
    protected final OutputStream out;

    public ScpHelper(InputStream in, OutputStream out, FileSystemView root) {
        this.in = in;
        this.out = out;
        this.root = root;
    }

    public void receive(SshFile path, boolean recursive, boolean shouldBeDir, boolean preserve, int bufferSize) throws IOException {
        if (shouldBeDir) {
            if (!path.doesExist()) {
                throw new SshException("Target directory " + path.toString() + " does not exists");
            }
            if (!path.isDirectory()) {
                throw new SshException("Target directory " + path.toString() + " is not a directory");
            }
        }
        ack();
        long[] time = null;
        for (;;)
        {
            String line;
            boolean isDir = false;
            int c = readAck(true);
            switch (c)
            {
                case -1:
                    return;
                case 'D':
                    isDir = true;
                case 'C':
                    line = ((char) c) + readLine();
                    log.debug("Received header: " + line);
                    break;
                case 'T':
                    line = ((char) c) + readLine();
                    log.debug("Received header: " + line);
                    time = parseTime(line);
                    ack();
                    continue;
                case 'E':
                    line = ((char) c) + readLine();
                    log.debug("Received header: " + line);
                    ack();
                    return;
                default:
                    //a real ack that has been acted upon already
                    continue;
            }

            if (recursive && isDir)
            {
                receiveDir(line, path, time, preserve, bufferSize);
                time = null;
            }
            else
            {
                receiveFile(line, path, time, preserve, bufferSize);
                time = null;
            }
        }
    }


    public void receiveDir(String header, SshFile path, long[] time, boolean preserve, int bufferSize) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Receiving directory {}", path);
        }
        if (!header.startsWith("D")) {
            throw new IOException("Expected a D message but got '" + header + "'");
        }

        String perms = header.substring(1, 5);
        int length = Integer.parseInt(header.substring(6, header.indexOf(' ', 6)));
        String name = header.substring(header.indexOf(' ', 6) + 1);

        if (length != 0) {
            throw new IOException("Expected 0 length for directory but got " + length);
        }
        SshFile file;
        if (path.doesExist() && path.isDirectory()) {
            file = root.getFile(path, name);
        } else if (!path.doesExist() && path.getParentFile().doesExist() && path.getParentFile().isDirectory()) {
            file = path;
        } else {
            throw new IOException("Can not write to " + path);
        }
        if (!(file.doesExist() && file.isDirectory()) && !file.mkdir()) {
            throw new IOException("Could not create directory " + file);
        }

        if (preserve) {
            Map<SshFile.Attribute, Object> attrs = new HashMap<SshFile.Attribute, Object>();
            attrs.put(SshFile.Attribute.Permissions, fromOctalPerms(perms));
            if (time != null) {
                attrs.put(SshFile.Attribute.LastModifiedTime, time[0]);
                attrs.put(SshFile.Attribute.LastAccessTime, time[1]);
            }
            file.setAttributes(attrs);
        }

        ack();

        time = null;
        for (;;) {
            header = readLine();
            log.debug("Received header: " + header);
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
                time = parseTime(header);
                ack();
            } else {
                throw new IOException("Unexpected message: '" + header + "'");
            }
        }
    }

    public void receiveFile(String header, SshFile path, long[] time, boolean preserve, int bufferSize) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Receiving file {}", path);
        }
        if (!header.startsWith("C")) {
            throw new IOException("Expected a C message but got '" + header + "'");
        }

        if (bufferSize < MIN_RECEIVE_BUFFER_SIZE) {
            throw new IOException("receiveFile(" + path + ") buffer size (" + bufferSize + ") below minimum (" + MIN_RECEIVE_BUFFER_SIZE + ")");
        }

        String perms = header.substring(1, 5);
        long length = Long.parseLong(header.substring(6, header.indexOf(' ', 6)));
        String name = header.substring(header.indexOf(' ', 6) + 1);
        if (length < 0L) { // TODO consider throwing an exception...
            log.warn("receiveFile(" + path + ") bad length in header: " + header);
        }

        // if file size is less than buffer size allocate only expected file size
        int bufSize;
        if (length == 0L) {
            if (log.isDebugEnabled()) {
                log.debug("receiveFile(" + path + ") zero file size (perhaps special file) using copy buffer size=" + MIN_RECEIVE_BUFFER_SIZE);
            }
            bufSize = MIN_RECEIVE_BUFFER_SIZE;
        } else {
            bufSize= (int) Math.min(length, bufferSize);
        }

        if (bufSize < 0) { // TODO consider throwing an exception
            log.warn("receiveFile(" + path + ") bad buffer size (" + bufSize + ") using default (" + MIN_RECEIVE_BUFFER_SIZE + ")");
            bufSize = MIN_RECEIVE_BUFFER_SIZE;
        }

        SshFile file;
        if (path.doesExist() && path.isDirectory()) {
            file = root.getFile(path, name);
        } else if (path.doesExist() && path.isFile()) {
            file = path;
        } else if (!path.doesExist() && path.getParentFile().doesExist() && path.getParentFile().isDirectory()) {
            file = path;
        } else {
            throw new IOException("Can not write to " + path);
        }

        if (file.doesExist() && file.isDirectory()) {
            throw new IOException("File is a directory: " + file);
        } else if (file.doesExist() && !file.isWritable()) {
            throw new IOException("Can not write to file: " + file);
        }

        if (file.doesExist()) {
            file.truncate();
        }

        OutputStream os = file.createOutputStream(0L);
        try {
            ack();

            byte[] buffer = new byte[bufSize];
            while (length > 0) {
                int len = (int) Math.min(length, buffer.length);
                len = in.read(buffer, 0, len);
                if (len <= 0) {
                    throw new IOException("End of stream reached");
                }
                os.write(buffer, 0, len);
                length -= len;
            }
        } finally {
            os.close();
        }

        if (preserve) {
            Map<SshFile.Attribute, Object> attrs = new HashMap<SshFile.Attribute, Object>();
            attrs.put(SshFile.Attribute.Permissions, fromOctalPerms(perms));
            if (time != null) {
                attrs.put(SshFile.Attribute.LastModifiedTime, time[0]);
                attrs.put(SshFile.Attribute.LastAccessTime, time[1]);
            }
            file.setAttributes(attrs);
        }

        ack();
        readAck(false);
    }

    public String readLine() throws IOException {
        return readLine(false);
    }

    public String readLine(boolean canEof) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (;;) {
            int c = in.read();
            if (c == '\n') {
                return baos.toString();
            } else if (c == -1) {
                if (!canEof) {
                    throw new EOFException();
                }
                return null;
            } else {
                baos.write(c);
            }
        }
    }

    public void send(List<String> paths, boolean recursive, boolean preserve, int bufferSize) throws IOException {
        readAck(false);
        for (String pattern : paths) {
            int idx = pattern.indexOf('*');
            if (idx >= 0) {
                String basedir = "";
                int lastSep = pattern.substring(0, idx).lastIndexOf('/');
                if (lastSep >= 0) {
                    basedir = pattern.substring(0, lastSep);
                    pattern = pattern.substring(lastSep + 1);
                }
                String[] included = new DirectoryScanner(basedir, pattern).scan();
                for (String path : included) {
                    SshFile file = root.getFile(basedir + "/" + path);
                    if (file.isFile()) {
                        sendFile(file, preserve, bufferSize);
                    } else if (file.isDirectory()) {
                        if (!recursive) {
                            out.write(ScpHelper.WARNING);
                            out.write((path + " not a regular file\n").getBytes());
                        } else {
                            sendDir(file, preserve, bufferSize);
                        }
                    } else {
                        out.write(ScpHelper.WARNING);
                        out.write((path + " unknown file type\n").getBytes());
                    }
                }
            } else {
                String basedir = "";
                int lastSep = pattern.lastIndexOf('/');
                if (lastSep >= 0) {
                    basedir = pattern.substring(0, lastSep);
                    pattern = pattern.substring(lastSep + 1);
                }
                SshFile file = root.getFile(basedir + "/" + pattern);
                if (!file.doesExist()) {
                    throw new IOException(file + ": no such file or directory");
                }
                if (file.isFile()) {
                    sendFile(file, preserve, bufferSize);
                } else if (file.isDirectory()) {
                    if (!recursive) {
                        throw new IOException(file + " not a regular file");
                    } else {
                        sendDir(file, preserve, bufferSize);
                    }
                } else {
                    throw new IOException(file + ": unknown file type");
                }
            }
        }
    }

    public void sendFile(SshFile path, boolean preserve, int bufferSize) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Sending file {}", path);
        }

        if (bufferSize < MIN_SEND_BUFFER_SIZE) {
            throw new IOException("sendFile(" + path + ") buffer size (" + bufferSize + ") below minimum (" + MIN_SEND_BUFFER_SIZE + ")");
        }

        Map<SshFile.Attribute,Object> attrs =  path.getAttributes(true);
        if (preserve) {
            StringBuffer buf = new StringBuffer();
            buf.append("T");
            buf.append(attrs.get(SshFile.Attribute.LastModifiedTime));
            buf.append(" ");
            buf.append("0");
            buf.append(" ");
            buf.append(attrs.get(SshFile.Attribute.LastAccessTime));
            buf.append(" ");
            buf.append("0");
            buf.append("\n");
            out.write(buf.toString().getBytes());
            out.flush();
            readAck(false);
        }

        StringBuffer buf = new StringBuffer();
        buf.append("C");
        buf.append(preserve ? toOctalPerms((EnumSet<SshFile.Permission>) attrs.get(SshFile.Attribute.Permissions)) : "0644");
        buf.append(" ");
        buf.append(attrs.get(SshFile.Attribute.Size)); // length
        buf.append(" ");
        buf.append(path.getName());
        buf.append("\n");
        out.write(buf.toString().getBytes());
        out.flush();
        readAck(false);

        long fileSize = path.getSize();
        if (fileSize < 0L) { // TODO consider throwing an exception...
            log.warn("sendFile(" + path + ") bad file size: " + fileSize);
        }

        // if file size is less than buffer size allocate only expected file size
        int bufSize;
        if (fileSize == 0L) {
            if (log.isDebugEnabled()) {
                log.debug("sendFile(" + path + ") zero file size (perhaps special file) using copy buffer size=" + MIN_SEND_BUFFER_SIZE);
            }
            bufSize = MIN_SEND_BUFFER_SIZE;
        } else {
            bufSize = (int) Math.min(fileSize, bufferSize);
        }

        if (bufSize < 0) { // TODO consider throwing an exception
            log.warn("sendFile(" + path + ") bad buffer size (" + bufSize + ") using default (" + MIN_SEND_BUFFER_SIZE + ")");
            bufSize = MIN_SEND_BUFFER_SIZE;
        }

        InputStream is = path.createInputStream(0L);
        try {
            byte[] buffer = new byte[bufSize];
            for (;;) {
                int len = is.read(buffer, 0, buffer.length);
                if (len == -1) {
                    break;
                }
                out.write(buffer, 0, len);
            }
        } finally {
            is.close();
        }
        ack();
        readAck(false);
    }

    public void sendDir(SshFile path, boolean preserve, int bufferSize) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Sending directory {}", path);
        }
        Map<SshFile.Attribute,Object> attrs =  path.getAttributes(true);
        if (preserve) {
            StringBuffer buf = new StringBuffer();
            buf.append("T");
            buf.append(attrs.get(SshFile.Attribute.LastModifiedTime));
            buf.append(" ");
            buf.append("0");
            buf.append(" ");
            buf.append(attrs.get(SshFile.Attribute.LastAccessTime));
            buf.append(" ");
            buf.append("0");
            buf.append("\n");
            out.write(buf.toString().getBytes());
            out.flush();
            readAck(false);
        }

        StringBuffer buf = new StringBuffer();
        buf.append("D");
        buf.append(preserve ? toOctalPerms((EnumSet<SshFile.Permission>) attrs.get(SshFile.Attribute.Permissions)) : "0755");
        buf.append(" ");
        buf.append("0"); // length
        buf.append(" ");
        buf.append(path.getName());
        buf.append("\n");
        out.write(buf.toString().getBytes());
        out.flush();
        readAck(false);

        for (SshFile child : path.listSshFiles()) {
            if (child.isFile()) {
                sendFile(child, preserve, bufferSize);
            } else if (child.isDirectory()) {
                sendDir(child, preserve, bufferSize);
            }
        }

        out.write("E\n".getBytes());
        out.flush();
        readAck(false);
    }

    private long[] parseTime(String line) {
        String[] numbers = line.substring(1).split(" ");
        return new long[] { Long.parseLong(numbers[0]), Long.parseLong(numbers[2]) };
    }

    public static String toOctalPerms(EnumSet<SshFile.Permission> perms) {
        int pf = 0;
        for (SshFile.Permission p : perms) {
            switch (p) {
                case UserRead:      pf |= S_IRUSR; break;
                case UserWrite:     pf |= S_IWUSR; break;
                case UserExecute:   pf |= S_IXUSR; break;
                case GroupRead:     pf |= S_IRGRP; break;
                case GroupWrite:    pf |= S_IWGRP; break;
                case GroupExecute:  pf |= S_IXGRP; break;
                case OthersRead:    pf |= S_IROTH; break;
                case OthersWrite:   pf |= S_IWOTH; break;
                case OthersExecute: pf |= S_IXOTH; break;
            }
        }
        return String.format("%04o", pf);
    }

    public static EnumSet<SshFile.Permission> fromOctalPerms(String str) {
        int perms = Integer.parseInt(str, 8);
        EnumSet<SshFile.Permission> p = EnumSet.noneOf(SshFile.Permission.class);
        if ((perms & S_IRUSR) != 0) {
            p.add(SshFile.Permission.UserRead);
        }
        if ((perms & S_IWUSR) != 0) {
            p.add(SshFile.Permission.UserWrite);
        }
        if ((perms & S_IXUSR) != 0) {
            p.add(SshFile.Permission.UserExecute);
        }
        if ((perms & S_IRGRP) != 0) {
            p.add(SshFile.Permission.GroupRead);
        }
        if ((perms & S_IWGRP) != 0) {
            p.add(SshFile.Permission.GroupWrite);
        }
        if ((perms & S_IXGRP) != 0) {
            p.add(SshFile.Permission.GroupExecute);
        }
        if ((perms & S_IROTH) != 0) {
            p.add(SshFile.Permission.OthersRead);
        }
        if ((perms & S_IWOTH) != 0) {
            p.add(SshFile.Permission.OthersWrite);
        }
        if ((perms & S_IXOTH) != 0) {
            p.add(SshFile.Permission.OthersExecute);
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
                    throw new EOFException();
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
