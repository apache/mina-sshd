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
package org.apache.sshd.server.shell;

import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.EnumSet;
import java.util.Map;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.Command;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link Factory} of {@link Command} that will create a new process and bridge
 * the streams.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ProcessShellFactory implements Factory<Command> {

    public enum TtyOptions {
        Echo,
        INlCr,
        ICrNl,
        ONlCr,
        OCrNl
    }

    private static final Logger LOG = LoggerFactory.getLogger(ProcessShellFactory.class);

    private String[] command;
    private EnumSet<TtyOptions> ttyOptions;

    public ProcessShellFactory() {
    }

    public ProcessShellFactory(String[] command) {
        this(command, EnumSet.noneOf(TtyOptions.class));
    }

    public ProcessShellFactory(String[] command, EnumSet<TtyOptions> ttyOptions) {
        this.command = command;
        this.ttyOptions = ttyOptions;
    }

    public String[] getCommand() {
        return command;
    }

    public void setCommand(String[] command) {
        this.command = command;
    }

    public Command create() {
        return new InvertedShellWrapper(new ProcessShell());
    }

    public class ProcessShell implements InvertedShell {

        private Process process;
        private TtyFilterOutputStream in;
        private TtyFilterInputStream out;
        private TtyFilterInputStream err;

        public void start(Map<String,String> env) throws IOException {
            String[] cmds = new String[command.length];
            for (int i = 0; i < cmds.length; i++) {
                if ("$USER".equals(command[i])) {
                    cmds[i] = env.get("USER");
                } else {
                    cmds[i] = command[i];
                }
            }
            ProcessBuilder builder = new ProcessBuilder(cmds);
            if (env != null) {
                try {
                    builder.environment().putAll(env);
                } catch (Exception e) {
                    LOG.info("Could not set environment for command", e);
                }
            }
            LOG.info("Starting shell with command: '{}' and env: {}", builder.command(), builder.environment());
            process = builder.start();
            out = new TtyFilterInputStream(process.getInputStream());
            err = new TtyFilterInputStream(process.getErrorStream());
            in = new TtyFilterOutputStream(process.getOutputStream(), err);
        }

        public OutputStream getInputStream() {
            return in;
        }

        public InputStream getOutputStream() {
            return out;
        }

        public InputStream getErrorStream() {
            return err;
        }

        public boolean isAlive() {
            try {
                process.exitValue();
                return false;
            } catch (IllegalThreadStateException e) {
                return true;
            }
        }

        public int exitValue() {
            return process.exitValue();
        }

        public void destroy() {
            process.destroy();
        }

        protected class TtyFilterInputStream extends FilterInputStream {
            private Buffer buffer;
            private int lastChar;
            public TtyFilterInputStream(InputStream in) {
                super(in);
                buffer = new Buffer(32);
            }
            synchronized void write(int c) {
                buffer.putByte((byte) c);
            }
            synchronized void write(byte[] buf, int off, int len) {
                buffer.putBytes(buf, off, len);
            }
            @Override
            public int available() throws IOException {
                return super.available() + buffer.available();
            }
            @Override
            public synchronized int read() throws IOException {
                int c;
                if (buffer.available() > 0) {
                    c = buffer.getByte();
                    buffer.compact();
                } else {
                    c = super.read();
                }
                if (c == '\n' && ttyOptions.contains(TtyOptions.ONlCr) && lastChar != '\r') {
                    c = '\r';
                    Buffer buf = new Buffer();
                    buf.putByte((byte) '\n');
                    buf.putBuffer(buffer);
                    buffer = buf;
                } else if (c == '\r' && ttyOptions.contains(TtyOptions.OCrNl)) {
                    c = '\n';
                }
                lastChar = c;
                return c;
            }
            @Override
            public synchronized int read(byte[] b, int off, int len) throws IOException {
                if (buffer.available() == 0) {
                    int nb = super.read(b, off, len);
                    buffer.putRawBytes(b, off, nb);
                }
                int nb = 0;
                while (nb < len && buffer.available() > 0) {
                    b[off + nb++] = (byte) read();
                }
                return nb;
            }
        }

        protected class TtyFilterOutputStream extends FilterOutputStream {
            private TtyFilterInputStream echo;
            public TtyFilterOutputStream(OutputStream out, TtyFilterInputStream echo) {
                super(out);
                this.echo = echo;
            }
            @Override
            public void write(int c) throws IOException {
                if (c == '\n' && ttyOptions.contains(TtyOptions.INlCr)) {
                    c = '\r';
                } else if (c == '\r' && ttyOptions.contains(TtyOptions.ICrNl)) {
                    c = '\n';
                }
                super.write(c);
                if (ttyOptions.contains(TtyOptions.Echo)) {
                    echo.write(c);
                }
            }
            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                for (int i = off; i < len; i++) {
                    write(b[i]);
                }
            }
        }
    }

}
