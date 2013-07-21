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
import java.util.List;

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

    protected final FileSystemView root;
    protected final InputStream in;
    protected final OutputStream out;

    public ScpHelper(InputStream in, OutputStream out, FileSystemView root) {
        this.in = in;
        this.out = out;
        this.root = root;
    }

    public void receive(SshFile path, boolean recursive, boolean shouldBeDir) throws IOException {
        if (shouldBeDir) {
            if (!path.doesExist()) {
                throw new SshException("Target directory " + path.toString() + " does not exists");
            }
            if (!path.isDirectory()) {
                throw new SshException("Target directory " + path.toString() + " is not a directory");
            }
        }
        ack();
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
                    break;
                case 'T':
                    readLine();
                    ack();
                    continue;
                case 'E':
                    readLine();
                    return;
                default:
                    //a real ack that has been acted upon already
                    continue;
            }

            if (recursive && isDir)
            {
                receiveDir(line, path);
            }
            else
            {
                receiveFile(line, path);
            }
        }
    }


    public void receiveDir(String header, SshFile path) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Writing dir {}", path);
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

        ack();

        for (;;) {
            header = readLine();
            if (header.startsWith("C")) {
                receiveFile(header, file);
            } else if (header.startsWith("D")) {
                receiveDir(header, file);
            } else if (header.equals("E")) {
                ack();
                break;
            } else if (header.equals("T")) {
                ack();
                break;
            } else {
                throw new IOException("Unexpected message: '" + header + "'");
            }
        }

    }

    public void receiveFile(String header, SshFile path) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Writing file {}", path);
        }
        if (!header.startsWith("C")) {
            throw new IOException("Expected a C message but got '" + header + "'");
        }

        String perms = header.substring(1, 5);
        long length = Long.parseLong(header.substring(6, header.indexOf(' ', 6)));
        String name = header.substring(header.indexOf(' ', 6) + 1);

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
        OutputStream os = file.createOutputStream(0);
        try {
            ack();

            byte[] buffer = new byte[8192];
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

    public void send(List<String> paths, boolean recursive) throws IOException {
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
                        sendFile(file);
                    } else if (file.isDirectory()) {
                        if (!recursive) {
                            out.write(ScpHelper.WARNING);
                            out.write((path + " not a regular file\n").getBytes());
                        } else {
                            sendDir(file);
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
                    sendFile(file);
                } else if (file.isDirectory()) {
                    if (!recursive) {
                        throw new IOException(file + " not a regular file");
                    } else {
                        sendDir(file);
                    }
                } else {
                    throw new IOException(file + ": unknown file type");
                }
            }
        }
    }

    public void sendFile(SshFile path) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Reading file {}", path);
        }
        StringBuffer buf = new StringBuffer();
        buf.append("C");
        buf.append("0644"); // TODO: what about perms
        buf.append(" ");
        buf.append(path.getSize()); // length
        buf.append(" ");
        buf.append(path.getName());
        buf.append("\n");
        out.write(buf.toString().getBytes());
        out.flush();
        readAck(false);

        InputStream is = path.createInputStream(0);
        try {
            byte[] buffer = new byte[8192];
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

    public void sendDir(SshFile path) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Reading directory {}", path);
        }
        StringBuffer buf = new StringBuffer();
        buf.append("D");
        buf.append("0755"); // what about perms
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
                sendFile(child);
            } else if (child.isDirectory()) {
                sendDir(child);
            }
        }

        out.write("E\n".getBytes());
        out.flush();
        readAck(false);
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
