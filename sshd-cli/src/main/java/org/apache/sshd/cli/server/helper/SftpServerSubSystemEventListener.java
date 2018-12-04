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

package org.apache.sshd.cli.server.helper;

import java.io.Flushable;
import java.io.IOException;
import java.nio.file.CopyOption;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.subsystem.sftp.SftpEventListener;
import org.apache.sshd.server.subsystem.sftp.SftpSubsystemFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpServerSubSystemEventListener implements SftpEventListener {
    private final Appendable stdout;
    private final Appendable stderr;

    public SftpServerSubSystemEventListener(Appendable stdout, Appendable stderr) {
        this.stdout = Objects.requireNonNull(stdout, "No output target");
        this.stderr = Objects.requireNonNull(stderr, "No error target");
    }

    public Appendable getStdout() {
        return stdout;
    }

    public Appendable getStderr() {
        return stderr;
    }

    @Override
    public void initialized(ServerSession session, int version) throws IOException {
        outputDebugMessage("Session %s initialized - version=%d", session, version);
    }

    @Override
    public void destroying(ServerSession session) throws IOException {
        outputDebugMessage("Session destroyed: %s", session);
    }

    @Override
    public void created(
            ServerSession session, Path path, Map<String, ?> attrs, Throwable thrown)
                throws IOException {
        if (thrown == null) {
            outputDebugMessage("Session %s created directory %s with attributes=%s", session, path, attrs);
        } else {
            outputErrorMessage("Failed (%s) to create directory %s in session %s: %s",
                thrown.getClass().getSimpleName(), path, session, thrown.getMessage());
        }
    }

    @Override
    public void moved(
            ServerSession session, Path srcPath, Path dstPath, Collection<CopyOption> opts, Throwable thrown)
                throws IOException {
        if (thrown == null) {
            outputDebugMessage("Session %s moved %s to %s with options=%s",
                session, srcPath, dstPath, opts);
        } else {
            outputErrorMessage("Failed (%s) to move %s to %s using options=%s in session %s: %s",
                thrown.getClass().getSimpleName(), srcPath, dstPath, opts, session, thrown.getMessage());
        }
    }

    @Override
    public void removed(ServerSession session, Path path, Throwable thrown) throws IOException {
        if (thrown == null) {
            outputDebugMessage("Session %s removed %s", session, path);
        } else {
            outputErrorMessage("Failed (%s) to remove %s in session %s: %s",
                thrown.getClass().getSimpleName(), path, session, thrown.getMessage());
        }
    }

    protected String outputErrorMessage(String format, Object... args) throws IOException {
        return outputMessage(getStderr(), format, args);
    }

    protected String outputDebugMessage(String format, Object... args) throws IOException {
        return outputMessage(getStdout(), format, args);
    }

    protected String outputMessage(Appendable out, String format, Object... args) throws IOException {
        String message = String.format(format, args);
        out.append(SftpSubsystemFactory.NAME)
            .append(": ").append(message)
            .append(System.lineSeparator());
        if (out instanceof Flushable) {
            ((Flushable) out).flush();
        }
        return message;
    }
}
