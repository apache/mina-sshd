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
package org.apache.sshd.util.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import org.apache.sshd.common.channel.BufferedIoOutputStream;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.io.IoInputStream;
import org.apache.sshd.common.io.IoOutputStream;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.server.ChannelSessionAware;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.channel.ChannelDataReceiver;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.AsyncCommand;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.shell.ShellFactory;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class AsyncEchoShellFactory implements ShellFactory {
    public AsyncEchoShellFactory() {
        super();
    }

    @Override
    public Command createShell(ChannelSession channel) {
        return new EchoShell();
    }

    public static class EchoShell implements AsyncCommand, ChannelDataReceiver, ChannelSessionAware {
        private IoOutputStream out;
        private IoOutputStream err;
        private ExitCallback callback;
        private Environment environment;
        private ChannelSession session;
        private StringBuilder buffer = new StringBuilder();

        public EchoShell() {
            super();
        }

        public IoOutputStream getOut() {
            return out;
        }

        public IoOutputStream getErr() {
            return err;
        }

        public Environment getEnvironment() {
            return environment;
        }

        @Override
        public void setInputStream(InputStream in) {
            // ignored
        }

        @Override
        public void setOutputStream(OutputStream out) {
            // ignored
        }

        @Override
        public void setErrorStream(OutputStream err) {
            // ignored
        }

        @Override
        public void setIoInputStream(IoInputStream in) {
            // ignored
        }

        @Override
        public void setIoOutputStream(IoOutputStream out) {
            this.out = new BufferedIoOutputStream("STDOUT", out);
        }

        @Override
        public void setIoErrorStream(IoOutputStream err) {
            this.err = new BufferedIoOutputStream("STDERR", err);
        }

        @Override
        public void setExitCallback(ExitCallback callback) {
            this.callback = callback;
        }

        @Override
        public void setChannelSession(ChannelSession session) {
            this.session = session;
        }

        @Override
        public void start(ChannelSession channel, Environment env) throws IOException {
            environment = env;
            session.setDataReceiver(this);
        }

        @Override
        public void close() throws IOException {
            out.close(false).addListener(future -> callback.onExit(0));
        }

        @Override
        public void destroy(ChannelSession channel) {
            // ignored
        }

        @Override
        public int data(ChannelSession channel, byte[] buf, int start, int len) throws IOException {
            buffer.append(new String(buf, start, len, StandardCharsets.UTF_8));
            for (int i = 0; i < buffer.length(); i++) {
                if (buffer.charAt(i) == '\n') {
                    String s = buffer.substring(0, i + 1);
                    byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
                    out.writeBuffer(new ByteArrayBuffer(bytes)).addListener(future -> {
                        Session session1 = channel.getSession();
                        if (future.isWritten()) {
                            try {
                                Window wLocal = channel.getLocalWindow();
                                wLocal.consumeAndCheck(bytes.length);
                            } catch (IOException e) {
                                session1.exceptionCaught(e);
                            }
                        } else {
                            Throwable t = future.getException();
                            session1.exceptionCaught(t);
                        }
                    });
                    buffer = new StringBuilder(buffer.substring(i + 1));
                    i = 0;
                }
            }
            return 0;
        }
    }
}
