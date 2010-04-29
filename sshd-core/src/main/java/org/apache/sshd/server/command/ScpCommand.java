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
package org.apache.sshd.server.command;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

import org.apache.sshd.common.util.DirectoryScanner;
import org.apache.sshd.common.util.SelectorUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.CommandFactory;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This commands provide SCP support on both server and client side.
 * Permissions and preservation of access / modification times on files
 * are not supported.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpCommand implements Command, Runnable {

    protected static final Logger log = LoggerFactory.getLogger(ScpCommand.class);
    protected static final int OK = 0;
    protected static final int WARNING = 1;
    protected static final int ERROR = 2;

    protected String name;
    protected boolean optR;
    protected boolean optT;
    protected boolean optF;
    protected boolean optV;
    protected boolean optD;
    protected boolean optP;
    protected String root;
    protected InputStream in;
    protected OutputStream out;
    protected OutputStream err;
    protected ExitCallback callback;
    protected IOException error;

    public ScpCommand(String[] args) {
        name = Arrays.asList(args).toString();
        if (log.isDebugEnabled()) {
            log.debug("Executing command {}", name);
        }
        root = ".";
        for (int i = 1; i < args.length; i++) {
            if (args[i].charAt(0) == '-') {
                for (int j = 1; j < args[i].length(); j++) {
                    switch (args[i].charAt(j)) {
                        case 'f':
                            optF = true;
                            break;
                        case 'p':
                            optP = true;
                            break;
                        case 'r':
                            optR = true;
                            break;
                        case 't':
                            optT = true;
                            break;
                        case 'v':
                            optV = true;
                            break;
                        case 'd':
                            optD = true;
                            break;
//                          default:
//                            error = new IOException("Unsupported option: " + args[i].charAt(j));
//                            return;
                    }
                }
            } else if (i == args.length - 1) {
                root = args[args.length - 1];
            }
        }
        if (!optF && !optT) {
            error = new IOException("Either -f or -t option should be set");
        }
    }

    public void setInputStream(InputStream in) {
        this.in = in;
    }

    public void setOutputStream(OutputStream out) {
        this.out = out;
    }

    public void setErrorStream(OutputStream err) {
        this.err = err;
    }

    public void setExitCallback(ExitCallback callback) {
        this.callback = callback;
    }

    public void start(Environment env) throws IOException {
        if (error != null) {
            throw error;
        }
        new Thread(this, "ScpCommand: " + name).start();
    }

    public void destroy() {
    }

    public void run() {
        int exitValue = OK;
        String exitMessage = null;
        
        try {
            if (optT)
            {
                ack();
                for (; ;)
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
                        case 'E':
                            line = ((char) c) + readLine();
                            break;
                        default:
                            //a real ack that has been acted upon already
                            continue;
                    }

                    if (optR && isDir)
                    {
                        writeDir(line, new File(root));
                    }
                    else
                    {
                        writeFile(line, new File(root));
                    }
                }
            } else if (optF) {
                String pattern = root;
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
                        File file = new File(basedir, path);
                        if (file.isFile()) {
                            readFile(file);
                        } else if (file.isDirectory()) {
                            if (!optR) {
                                out.write(WARNING);
                                out.write((path + " not a regular file\n").getBytes());
                            } else {
                                readDir(file);
                            }
                        } else {
                            out.write(WARNING);
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
                    File file = new File(basedir, pattern);
                    if (!file.exists()) {
                        throw new IOException(file + ": no such file or directory");
                    }
                    if (file.isFile()) {
                        readFile(file);
                    } else if (file.isDirectory()) {
                        if (!optR) {
                            throw new IOException(file + " not a regular file");
                        } else {
                            readDir(file);
                        }
                    } else {
                        throw new IOException(file + ": unknown file type");
                    }
                }
            } else {
                throw new IOException("Unsupported mode");
            }
        } catch (IOException e) {
            try {
                exitValue = ERROR;
                exitMessage = e.getMessage();
                out.write(exitValue);
                out.write(exitMessage.getBytes());
                out.write('\n');
                out.flush();
            } catch (IOException e2) {
                // Ignore
            }
            log.info("Error in scp command", e);
        } finally {
            if (callback != null) {
                callback.onExit(exitValue, exitMessage);
            }
        }
    }

    protected void writeDir(String header, File path) throws IOException {
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
        File file;
        if (path.exists() && path.isDirectory()) {
            file = new File(path, name);
        } else if (!path.exists() && path.getParentFile().exists() && path.getParentFile().isDirectory()) {
            file = path;
        } else {
            throw new IOException("Can not write to " + path);
        }
        if (!(file.exists() && file.isDirectory()) && !file.mkdir()) {
            throw new IOException("Could not create directory " + file);
        }

        ack();

        for (;;) {
            header = readLine();
            if (header.startsWith("C")) {
                writeFile(header, file);
            } else if (header.startsWith("D")) {
                writeDir(header, file);
            } else if (header.equals("E")) {
                ack();
                break;
            } else {
                throw new IOException("Unexpected message: '" + header + "'");
            }
        }

    }

    protected void writeFile(String header, File path) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Writing file {}", path);
        }
        if (!header.startsWith("C")) {
            throw new IOException("Expected a C message but got '" + header + "'");
        }

        String perms = header.substring(1, 5);
        long length = Long.parseLong(header.substring(6, header.indexOf(' ', 6)));
        String name = header.substring(header.indexOf(' ', 6) + 1);

        File file;
        if (path.exists() && path.isDirectory()) {
            file = new File(path, name);
        } else if (path.exists() && path.isFile()) {
            file = path;
        } else if (!path.exists() && path.getParentFile().exists() && path.getParentFile().isDirectory()) {
            file = path;
        } else {
            throw new IOException("Can not write to " + path);
        }
        if (file.exists() && file.isDirectory()) {
            throw new IOException("File is a directory: " + file);
        } else if (file.exists() && !file.canWrite()) {
            throw new IOException("Can not write to file: " + file);
        }
        OutputStream os = new FileOutputStream(file);
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

    protected String readLine() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (;;) {
            int c = in.read();
            if (c == '\n') {
                return baos.toString();
            } else if (c == -1) {
                throw new IOException("End of stream");
            } else {
                baos.write(c);
            }
        }
    }

    protected void readFile(File path) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Reading file {}", path);
        }
        StringBuffer buf = new StringBuffer();
        buf.append("C");
        buf.append("0644"); // what about perms
        buf.append(" ");
        buf.append(path.length()); // length
        buf.append(" ");
        buf.append(path.getName());
        buf.append("\n");
        out.write(buf.toString().getBytes());
        out.flush();
        readAck(false);

        InputStream is = new FileInputStream(path);
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

    protected void readDir(File path) throws IOException {
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

        for (File child : path.listFiles()) {
            if (child.isFile()) {
                readFile(child);
            } else if (child.isDirectory()) {
                readDir(child);
            }
        }

        out.write("E\n".getBytes());
        out.flush();
        readAck(false);
    }

    protected void ack() throws IOException {
        out.write(0);
        out.flush();
    }

    protected int readAck(boolean canEof) throws IOException {
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
