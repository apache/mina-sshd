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
package org.apache.sshd.sftp.client.impl;

import java.io.Closeable;
import java.io.IOException;
import java.nio.channels.Channel;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.DirEntry;
import org.apache.sshd.sftp.client.SftpClient.Handle;

/**
 * Iterates over the available directory entries for a given path. <B>Note:</B> if the iteration is carried out until no
 * more entries are available, then no need to close the iterator. Otherwise, it is recommended to close it so as to
 * release the internal handle.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpDirEntryIterator extends AbstractLoggingBean implements Iterator<DirEntry>, Channel {
    private final AtomicReference<Boolean> eolIndicator = new AtomicReference<>();
    private final AtomicBoolean open = new AtomicBoolean(true);
    private final SftpClient client;
    private final String dirPath;
    private final boolean closeOnFinished;
    private Handle dirHandle;
    private List<DirEntry> dirEntries;
    private int index;

    /**
     * @param  client      The {@link SftpClient} instance to use for the iteration
     * @param  path        The remote directory path
     * @throws IOException If failed to gain access to the remote directory path
     */
    public SftpDirEntryIterator(SftpClient client, String path) throws IOException {
        this(client, path, client.openDir(path), true);
    }

    /**
     * @param client    The {@link SftpClient} instance to use for the iteration
     * @param dirHandle The directory {@link Handle} to use for listing the entries
     */
    public SftpDirEntryIterator(SftpClient client, Handle dirHandle) {
        this(client, Objects.toString(dirHandle, null), dirHandle, false);
    }

    /**
     * @param client          The {@link SftpClient} instance to use for the iteration
     * @param path            A hint as to the remote directory path - used only for logging
     * @param dirHandle       The directory {@link Handle} to use for listing the entries
     * @param closeOnFinished If {@code true} then close the directory handle when all entries have been exhausted
     */
    public SftpDirEntryIterator(SftpClient client, String path, Handle dirHandle, boolean closeOnFinished) {
        this.client = Objects.requireNonNull(client, "No SFTP client instance");
        this.dirPath = ValidateUtils.checkNotNullAndNotEmpty(path, "No path");
        this.dirHandle = Objects.requireNonNull(dirHandle, "No directory handle");
        this.closeOnFinished = closeOnFinished;
        this.dirEntries = load(dirHandle);
    }

    /**
     * The client instance
     *
     * @return {@link SftpClient} instance used to access the remote folder
     */
    public final SftpClient getClient() {
        return client;
    }

    /**
     * The remotely accessed directory path
     *
     * @return Remote directory hint - may be the handle's value if accessed directly via a {@link Handle} instead of
     *         via a path - used only for logging
     */
    public final String getPath() {
        return dirPath;
    }

    /**
     * @return The directory {@link Handle} used to access the remote directory
     */
    public final Handle getHandle() {
        return dirHandle;
    }

    @Override
    public boolean hasNext() {
        return (dirEntries != null) && (index < dirEntries.size());
    }

    @Override
    public DirEntry next() {
        DirEntry entry = dirEntries.get(index++);
        if (index >= dirEntries.size()) {
            index = 0;

            try {
                dirEntries = load(getHandle());
            } catch (RuntimeException e) {
                dirEntries = null;
                throw e;
            }
        }

        return entry;
    }

    @Override
    public boolean isOpen() {
        return open.get();
    }

    public boolean isCloseOnFinished() {
        return closeOnFinished;
    }

    @Override
    public void close() throws IOException {
        if (open.getAndSet(false)) {
            Handle handle = getHandle();
            if ((handle instanceof Closeable) && isCloseOnFinished()) {
                if (log.isDebugEnabled()) {
                    log.debug("close(" + getPath() + ") handle=" + handle);
                }
                ((Closeable) handle).close();
            }
        }
    }

    protected List<DirEntry> load(Handle handle) {
        try {
            // check if previous call yielded an end-of-list indication
            Boolean eolReached = eolIndicator.getAndSet(null);
            if ((eolReached != null) && eolReached) {
                if (log.isTraceEnabled()) {
                    log.trace("load({})[{}] exhausted all entries on previous call", getPath(), handle);
                }
                return null;
            }

            List<DirEntry> entries = client.readDir(handle, eolIndicator);
            eolReached = eolIndicator.get();
            if ((entries == null) || ((eolReached != null) && eolReached)) {
                if (log.isTraceEnabled()) {
                    log.trace("load({})[{}] exhausted all entries - EOL={}", getPath(), handle, eolReached);
                }
                close();
            }

            return entries;
        } catch (IOException e) {
            try {
                close();
            } catch (IOException t) {
                e.addSuppressed(t);
                debug("{} while close handle={} due to {} [{}]: {}",
                        t.getClass().getSimpleName(), handle, e.getClass().getSimpleName(), e.getMessage(), t);
            }
            throw new RuntimeException(e);
        }
    }

    @Override
    public void remove() {
        throw new UnsupportedOperationException("readDir(" + getPath() + ")[" + getHandle() + "] Iterator#remove() N/A");
    }
}
