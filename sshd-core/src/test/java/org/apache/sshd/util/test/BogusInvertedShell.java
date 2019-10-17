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
import java.util.Collections;
import java.util.Map;

import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.shell.InvertedShell;

public class BogusInvertedShell implements InvertedShell {
    private final OutputStream in;
    private final InputStream out;
    private final InputStream err;

    // for test assertions
    private ServerSession session;
    private ChannelSession channel;
    private boolean started;
    private boolean alive = true;
    private Map<String, String> env;

    public BogusInvertedShell(OutputStream in, InputStream out, InputStream err) {
        this.in = in;
        this.out = out;
        this.err = err;
    }

    @Override
    public ServerSession getServerSession() {
        return session;
    }

    @Override
    public void setSession(ServerSession session) {
        this.session = session;
    }

    @Override
    public ChannelSession getChannelSession() {
        return channel;
    }

    @Override
    public void start(ChannelSession channel, Environment env) throws IOException {
        this.channel = channel;
        this.started = true;
        this.env = Collections.unmodifiableMap(env.getEnv());
    }

    @Override
    public OutputStream getInputStream() {
        return in;
    }

    @Override
    public InputStream getOutputStream() {
        return out;
    }

    @Override
    public InputStream getErrorStream() {
        return err;
    }

    @Override
    public boolean isAlive() {
        return alive;
    }

    @Override
    public int exitValue() {
        return 0;
    }

    @Override
    public void destroy(ChannelSession channel) {
        IoUtils.closeQuietly(in, out, err);
    }

    public boolean isStarted() {
        return started;
    }

    public Map<String, String> getEnv() {
        return env;
    }

    public void setAlive(boolean alive) {
        this.alive = alive;
    }
}
