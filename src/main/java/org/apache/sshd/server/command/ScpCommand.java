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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.sshd.server.CommandFactory;

/**
 * This commands provide SCP support on both server and client side.
 * Permissions and preservation of access / modification times on files
 * are not supported.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public class ScpCommand implements CommandFactory.Command, Runnable {

    private boolean optR;
    private boolean optT;
    private boolean optF;
    private boolean optV;
    private boolean optP;
    private File root;
    private InputStream in;
    private OutputStream out;
    private OutputStream err;
    private CommandFactory.ExitCallback callback;
    private IOException error;

    public ScpCommand(String[] args) {
        root = new File(".");
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
//                          default:
//                            error = new IOException("Unsupported option: " + args[i].charAt(j));
//                            return;
                    }
                }
            } else if (i == args.length - 1) {
                root = new File(args[args.length - 1]);
            }
            if (!optF && !optT) {
                error = new IOException("Either -f or -t option should be set");
            }
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

    public void setExitCallback(CommandFactory.ExitCallback callback) {
        this.callback = callback;
    }

    public void start() throws IOException {
        if (error != null) {
            throw error;
        }
        new Thread(this).start();
    }

    public void run() {
        try {
            if (optT && !optR) {
                ack();
                writeFile(readLine(), root);
            } else if (optT && optR) {
                ack();
                writeDir(readLine(), root);
            } else if (optF) {
                if (!root.exists()) {
                    throw new IOException(root + ": no such file or directory");
                }
                if (root.isFile()) {
                    readFile(root);
                } else if (root.isDirectory()) {
                    if (!optR) {
                        throw new IOException(root + " not a regular file");
                    } else {
                        readDir(root);
                    }
                } else {
                    throw new IOException(root + ": unknown file type");
                }
            } else {
                throw new IOException("Unsupported mode");
            }
        } catch (IOException e) {
            try {
                out.write(2);
                out.write(e.getMessage().getBytes());
                out.write('\n');
                out.flush();
            } catch (IOException e2) {
                // Ignore
            }
            e.printStackTrace();
        } finally {
            callback.onExit(0);
        }
    }

    private void writeDir(String header, File path) throws IOException {
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

    private void writeFile(String header, File path) throws IOException {
        if (!header.startsWith("C")) {
            throw new IOException("Expected a C message but got '" + header + "'");
        }

        String perms = header.substring(1, 5);
        int length = Integer.parseInt(header.substring(6, header.indexOf(' ', 6)));
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
        OutputStream os = new FileOutputStream(file);

        ack();

        byte[] buffer = new byte[8192];
        while (length > 0) {
            int len = Math.min(length, buffer.length);
            len = in.read(buffer, 0, len);
            if (len <= 0) {
                throw new IOException("End of stream reached");
            }
            os.write(buffer, 0, len);
            length -= len;
        }
        os.close();

        ack();
        readAck();
    }

    private String readLine() throws IOException {
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

    private void readFile(File path) throws IOException {
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
        readAck();

        InputStream is = new FileInputStream(path);
        byte[] buffer = new byte[8192];
        for (;;) {
            int len = is.read(buffer, 0, buffer.length);
            if (len == -1) {
                break;
            }
            out.write(buffer, 0, len);
        }
        is.close();
        ack();
        readAck();
    }

    private void readDir(File path) throws IOException {
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
        readAck();

        for (File child : path.listFiles()) {
            if (child.isFile()) {
                readFile(child);
            } else if (child.isDirectory()) {
                readDir(child);
            }
        }

        out.write("E\n".getBytes());
        out.flush();
        readAck();
    }

    private void ack() throws IOException {
        out.write(0);
        out.flush();
    }

    private void readAck() throws IOException {
        int c = in.read();
        switch (c) {
            case 0:
                break;
            case 1:
                System.out.println("Received warning: " + readLine());
                break;
            case 2:
                throw new IOException("Received nack: " + readLine());
        }
    }

}
