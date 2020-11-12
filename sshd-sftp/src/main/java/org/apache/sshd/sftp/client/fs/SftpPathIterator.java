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

package org.apache.sshd.sftp.client.fs;

import java.io.IOException;
import java.nio.file.DirectoryIteratorException;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Objects;

import org.apache.sshd.sftp.client.SftpClient;

/**
 * Implements and {@link Iterator} of {@link SftpPath}-s returned by a {@link DirectoryStream#iterator()} method.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpPathIterator implements Iterator<Path> {
    protected final Iterator<? extends SftpClient.DirEntry> it;
    protected boolean dotIgnored;
    protected boolean dotdotIgnored;
    protected SftpPath curEntry;

    private final SftpPath path;
    private DirectoryStream.Filter<? super Path> filter;

    public SftpPathIterator(SftpPath path, Iterable<? extends SftpClient.DirEntry> iter) {
        this(path, iter, null);
    }

    public SftpPathIterator(SftpPath path, Iterable<? extends SftpClient.DirEntry> iter,
                            DirectoryStream.Filter<? super Path> filter) {
        this(path, (iter == null) ? null : iter.iterator(), filter);
    }

    public SftpPathIterator(SftpPath path, Iterator<? extends SftpClient.DirEntry> iter) {
        this(path, iter, null);
    }

    public SftpPathIterator(SftpPath path, Iterator<? extends SftpClient.DirEntry> iter,
                            DirectoryStream.Filter<? super Path> filter) {
        this.path = Objects.requireNonNull(path, "No root path provided");
        this.filter = filter;

        it = iter;
        curEntry = nextEntry(path, filter);
    }

    /**
     * @return The root {@link SftpPath} for this directory iterator
     */
    public final SftpPath getRootPath() {
        return path;
    }

    /**
     * @return The original filter - may be {@code null} to indicate no filter
     */
    public final Filter<? super Path> getFilter() {
        return filter;
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

        SftpPath returnValue = curEntry;
        curEntry = nextEntry(getRootPath(), getFilter());
        return returnValue;
    }

    protected SftpPath nextEntry(SftpPath root, DirectoryStream.Filter<? super Path> selector) {
        while ((it != null) && it.hasNext()) {
            SftpClient.DirEntry entry = it.next();
            String name = entry.getFilename();
            if (".".equals(name) && (!dotIgnored)) {
                dotIgnored = true;
            } else if ("..".equals(name) && (!dotdotIgnored)) {
                dotdotIgnored = true;
            } else {
                SftpPath candidate = root.resolve(entry.getFilename());
                try {
                    if ((selector == null) || selector.accept(candidate)) {
                        return candidate;
                    }
                } catch (IOException e) {
                    throw new DirectoryIteratorException(e);
                }
            }
        }

        return null;
    }

    @Override
    public void remove() {
        throw new UnsupportedOperationException("newDirectoryStream(" + getRootPath() + ") Iterator#remove() N/A");
    }
}
