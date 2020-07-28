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
package org.apache.sshd.sftp.server;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;
import java.util.Iterator;

import org.apache.sshd.server.session.ServerSession;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DirectoryHandle extends Handle implements Iterator<Path> {
    private boolean done;
    private boolean sendDotDot = true;
    private boolean sendDot = true;
    // the directory should be read once at "open directory"
    private DirectoryStream<Path> ds;
    private Iterator<Path> fileList;

    public DirectoryHandle(SftpSubsystem subsystem, Path dir, String handle) throws IOException {
        super(subsystem, dir, handle);

        SftpFileSystemAccessor accessor = subsystem.getFileSystemAccessor();
        ServerSession session = subsystem.getServerSession();
        signalHandleOpening();
        ds = accessor.openDirectory(session, subsystem, this, dir, handle);

        Path parent = dir.getParent();
        if (parent == null) {
            sendDotDot = false; // if no parent then no need to send ".."
        }
        fileList = ds.iterator();

        try {
            signalHandleOpen();
        } catch (IOException e) {
            close();
            throw e;
        }
    }

    public boolean isDone() {
        return done;
    }

    public void markDone() {
        this.done = true;
        // allow the garbage collector to do the job
        this.fileList = null;
    }

    public boolean isSendDot() {
        return sendDot;
    }

    public void markDotSent() {
        sendDot = false;
    }

    public boolean isSendDotDot() {
        return sendDotDot;
    }

    public void markDotDotSent() {
        sendDotDot = false;
    }

    @Override
    public boolean hasNext() {
        return fileList.hasNext();
    }

    @Override
    public Path next() {
        return fileList.next();
    }

    @Override
    public void remove() {
        throw new UnsupportedOperationException("Not allowed to remove " + toString());
    }

    @Override
    public void close() throws IOException {
        try {
            SftpSubsystem subsystem = getSubsystem();
            SftpFileSystemAccessor accessor = subsystem.getFileSystemAccessor();
            ServerSession session = subsystem.getServerSession();
            accessor.closeDirectory(session, subsystem, this, getFile(), getFileHandle(), ds);
        } finally {
            super.close();
            markDone(); // just making sure
        }
    }
}
