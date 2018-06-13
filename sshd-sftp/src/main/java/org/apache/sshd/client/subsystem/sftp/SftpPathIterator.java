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

package org.apache.sshd.client.subsystem.sftp;

import java.nio.file.Path;
import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpPathIterator implements Iterator<Path> {
    private final SftpPath p;
    private final Iterator<? extends SftpClient.DirEntry> it;
    private boolean dotIgnored;
    private boolean dotdotIgnored;
    private SftpClient.DirEntry curEntry;

    public SftpPathIterator(SftpPath path, Iterable<? extends SftpClient.DirEntry> iter) {
        this(path, (iter == null) ? null : iter.iterator());
    }

    public SftpPathIterator(SftpPath path, Iterator<? extends SftpClient.DirEntry> iter) {
        p = path;
        it = iter;
        curEntry = nextEntry();
    }

    @Override
    public boolean hasNext() {
        return curEntry != null;
    }

    @Override
    public Path next() {
        if (curEntry == null) {
            throw new NoSuchElementException("No next entry");
        }

        SftpClient.DirEntry entry = curEntry;
        curEntry = nextEntry();
        return p.resolve(entry.getFilename());
    }

    private SftpClient.DirEntry nextEntry() {
        while ((it != null) && it.hasNext()) {
            SftpClient.DirEntry entry = it.next();
            String name = entry.getFilename();
            if (".".equals(name) && (!dotIgnored)) {
                dotIgnored = true;
            } else if ("..".equals(name) && (!dotdotIgnored)) {
                dotdotIgnored = true;
            } else {
                return entry;
            }
        }

        return null;
    }

    @Override
    public void remove() {
        throw new UnsupportedOperationException("newDirectoryStream(" + p + ") Iterator#remove() N/A");
    }
}