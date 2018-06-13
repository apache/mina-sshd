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
package org.apache.sshd.server.subsystem.sftp;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.server.session.ServerSession;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class Handle implements java.nio.channels.Channel {
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final Path file;
    private final String handle;

    protected Handle(Path file, String handle) {
        this.file = Objects.requireNonNull(file, "No local file path");
        this.handle = ValidateUtils.checkNotNullAndNotEmpty(handle, "No assigned handle for %s", file);
    }

    protected void signalHandleOpening(SftpSubsystem subsystem) throws IOException {
        SftpEventListener listener = subsystem.getSftpEventListenerProxy();
        ServerSession session = subsystem.getServerSession();
        listener.opening(session, handle, this);
    }

    protected void signalHandleOpen(SftpSubsystem subsystem) throws IOException {
        SftpEventListener listener = subsystem.getSftpEventListenerProxy();
        ServerSession session = subsystem.getServerSession();
        listener.open(session, handle, this);
    }

    public Path getFile() {
        return file;
    }

    public String getFileHandle() {
        return handle;
    }

    @Override
    public boolean isOpen() {
        return !closed.get();
    }

    @Override
    public void close() throws IOException {
        if (!closed.getAndSet(true)) {
            //noinspection UnnecessaryReturnStatement
            return; // debug breakpoint
        }
    }

    @Override
    public String toString() {
        return Objects.toString(getFile());
    }
}
