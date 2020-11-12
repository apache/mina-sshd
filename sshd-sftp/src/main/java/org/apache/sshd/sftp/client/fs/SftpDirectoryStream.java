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
import java.nio.file.DirectoryStream;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.Objects;

import org.apache.sshd.sftp.client.SftpClient;

/**
 * Implements a remote {@link DirectoryStream}
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpDirectoryStream implements DirectoryStream<Path> {
    protected SftpPathIterator pathIterator;

    private final SftpPath path;
    private final Filter<? super Path> filter;
    private final SftpClient sftp;

    /**
     * @param  path        The remote {@link SftpPath}
     * @throws IOException If failed to initialize the directory access handle
     */
    public SftpDirectoryStream(SftpPath path) throws IOException {
        this(path, null);
    }

    /**
     *
     * @param  path        The remote {@link SftpPath}
     * @param  filter      An <U>optional</U> {@link java.nio.file.DirectoryStream.Filter filter} - ignored if
     *                     {@code null}
     * @throws IOException If failed to initialize the directory access handle
     */
    public SftpDirectoryStream(SftpPath path, Filter<? super Path> filter) throws IOException {
        this.path = Objects.requireNonNull(path, "No path specified");
        this.filter = filter;

        SftpFileSystem fs = path.getFileSystem();
        sftp = fs.getClient();

        Iterable<SftpClient.DirEntry> iter = sftp.readDir(path.toString());
        pathIterator = new SftpPathIterator(getRootPath(), iter, getFilter());
    }

    /**
     * Client instance used to access the remote directory
     *
     * @return The {@link SftpClient} instance used to access the remote directory
     */
    public final SftpClient getClient() {
        return sftp;
    }

    /**
     * @return The root {@link SftpPath} for this directory stream
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
    public Iterator<Path> iterator() {
        if (!sftp.isOpen()) {
            throw new IllegalStateException("Stream has been closed");
        }

        /*
         * According to documentation this method can be called only once
         */
        if (pathIterator == null) {
            throw new IllegalStateException("Iterator has already been consumed");
        }

        Iterator<Path> iter = pathIterator;
        pathIterator = null;
        return iter;
    }

    @Override
    public void close() throws IOException {
        sftp.close();
    }
}
