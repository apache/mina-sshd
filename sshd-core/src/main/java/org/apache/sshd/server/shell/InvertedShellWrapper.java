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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

import org.apache.sshd.server.ShellFactory;
import org.apache.sshd.server.ShellFactory.Environment;

/**
 * A shell implementation that wraps an instance of {@link InvertedShell}
 * as a {@link ShellFactory.Shell}.  This is useful when using external
 * processes.
 * When starting the shell, this wrapper will also create a thread used
 * to pump the streams and also to check if the shell is alive. 
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class InvertedShellWrapper implements ShellFactory.Shell {

    private final InvertedShell shell;
    private InputStream in;
    private OutputStream out;
    private OutputStream err;
    private OutputStream shellIn;
    private InputStream shellOut;
    private InputStream shellErr;
    private ShellFactory.ExitCallback callback;
    private Thread thread;

    public InvertedShellWrapper(InvertedShell shell) {
        this.shell = shell;
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

    public void setExitCallback(ShellFactory.ExitCallback callback) {
        this.callback = callback;
    }

    public void start(Environment env) throws IOException {
        // TODO propagate the Environment itself and support signal sending.
        shell.start(env.getEnv());
        shellIn = shell.getInputStream();
        shellOut = shell.getOutputStream();
        shellErr = shell.getErrorStream();
        thread = new Thread("inverted-shell-pump") {
            @Override
            public void run() {
                pumpStreams();
            }
        };
        thread.start();
    }

    public void destroy() {
        shell.destroy();
    }

    protected void pumpStreams() {
        try {
            // Use a single thread to correctly sequence the output and error streams.
            // If any bytes are available from the output stream, send them first, then
            // check the error stream, or wait until more data is available.
            byte[] buffer = new byte[512];
            for (;;) {
                if (!shell.isAlive()) {
                    callback.onExit(shell.exitValue());
                    return;
                }
                if (pumpStream(in, shellIn, buffer)) {
                    continue;
                }
                if (pumpStream(shellOut, out, buffer)) {
                    continue;
                }
                if (pumpStream(shellErr, err, buffer)) {
                    continue;
                }
                // Sleep a bit.  This is not very good, as it consumes CPU, but the
                // input streams are not selectable for nio, and any other blocking
                // method would consume at least two threads
                Thread.sleep(1);
            }
        } catch (Exception e) {
            shell.destroy();
            callback.onExit(shell.exitValue());
        }
    }

    private boolean pumpStream(InputStream in, OutputStream out, byte[] buffer) throws IOException {
        if (in.available() > 0) {
            int len = in.read(buffer);
            if (len > 0) {
                out.write(buffer, 0, len);
                out.flush();
                return true;
            }
        }
        return false;
    }

}
