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

import java.io.Closeable;
import java.io.IOException;
import java.util.Iterator;
import java.util.NoSuchElementException;

import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.DirEntry;
import org.apache.sshd.sftp.client.fs.SftpPath;
import org.apache.sshd.sftp.client.impl.SftpIterableDirEntry;

public class RemoteDirectoryHandle extends Handle implements Iterator<SftpClient.DirEntry> {

    private final SftpIterableDirEntry entries;

    private Iterator<SftpClient.DirEntry> iterator;

    private boolean atStart = true;

    private boolean done;

    protected RemoteDirectoryHandle(SftpSubsystem subsystem, SftpPath file, String handle) throws IOException {
        super(subsystem, file, handle);
        entries = new SftpIterableDirEntry(file.getFileSystem().getClient(), file.toString());
    }

    public boolean isAtStart() {
        return atStart;
    }

    public int getSftpVersion() {
        return entries.getClient().getVersion();
    }

    @Override
    public boolean hasNext() {
        if (done) {
            return false;
        }
        if (iterator == null) {
            iterator = entries.iterator();
        }
        done = !iterator.hasNext();
        return !done;
    }

    @Override
    public DirEntry next() {
        if (!hasNext()) {
            throw new NoSuchElementException("No more entries to iterate for " + getFile());
        }
        atStart = false;
        return iterator.next();
    }

    @Override
    public void close() throws IOException {
        done = true;
        atStart = false;
        Closeable toClose = null;
        if (iterator != null && iterator instanceof Closeable) {
            toClose = (Closeable) iterator;
        }
        iterator = null;
        try {
            super.close();
        } finally {
            if (toClose != null) {
                toClose.close();
            }
        }
    }
}
