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

import java.io.IOException;
import java.nio.channels.Channel;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.client.subsystem.sftp.SftpClient.CloseableHandle;
import org.apache.sshd.client.subsystem.sftp.SftpClient.DirEntry;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * Iterates over the available directory entries for a given path. <B>Note:</B>
 * if the iteration is carried out until no more entries are available, then
 * no need to close the iterator. Otherwise, it is recommended to close it so
 * as to release the internal handle.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpDirEntryIterator extends AbstractLoggingBean implements Iterator<DirEntry>, Channel {
    private final AtomicReference<Boolean> eolIndicator = new AtomicReference<>();
    private final SftpClient client;
    private final String dirPath;
    private CloseableHandle dirHandle;
    private List<DirEntry> dirEntries;
    private int index;

    /**
     * @param client The {@link SftpClient} instance to use for the iteration
     * @param path The remote directory path
     */
    public SftpDirEntryIterator(SftpClient client, String path) {
        this.client = ValidateUtils.checkNotNull(client, "No SFTP client instance");
        this.dirPath = path;
        this.dirHandle = open(path);
        this.dirEntries = load(dirHandle);
    }

    /**
     * The client instance
     *
     * @return {@link SftpClient} instance used to access the remote file
     */
    public final SftpClient getClient() {
        return client;
    }

    /**
     * The remotely accessed directory path
     *
     * @return Remote directory path
     */
    public final String getPath() {
        return dirPath;
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
                dirEntries = load(dirHandle);
            } catch (RuntimeException e) {
                dirEntries = null;
                throw e;
            }
        }

        return entry;
    }

    @Override
    public boolean isOpen() {
        return (dirHandle != null) && dirHandle.isOpen();
    }

    @Override
    public void close() throws IOException {
        if (isOpen()) {
            if (log.isDebugEnabled()) {
                log.debug("close(" + getPath() + ") handle=" + dirHandle);
            }
            dirHandle.close();
        }
    }

    protected CloseableHandle open(String path) {
        try {
            CloseableHandle handle = client.openDir(path);
            if (log.isDebugEnabled()) {
                log.debug("open(" + path + ") handle=" + handle);
            }

            return handle;
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("open(" + path + ") failed (" + e.getClass().getSimpleName() + ") to open dir: " + e.getMessage());
            }
            throw new RuntimeException(e);
        }
    }

    protected List<DirEntry> load(CloseableHandle handle) {
        try {
            // check if previous call yielded an end-of-list indication
            Boolean eolReached = eolIndicator.getAndSet(null);
            if ((eolReached != null) && eolReached.booleanValue()) {
                if (log.isTraceEnabled()) {
                    log.trace("load({}) exhausted all entries on previous call", getPath());
                }
                return null;
            }

            List<DirEntry> entries = client.readDir(handle, eolIndicator);
            eolReached = eolIndicator.get();
            if ((entries == null) || ((eolReached != null) && eolReached.booleanValue())) {
                if (log.isTraceEnabled()) {
                    log.trace("load({}) exhausted all entries - EOL={}", getPath(), eolReached);
                }
                close();
            }

            return entries;
        } catch (IOException e) {
            try {
                close();
            } catch (IOException t) {
                if (log.isTraceEnabled()) {
                    log.trace(t.getClass().getSimpleName() + " while close handle=" + handle
                            + " due to " + e.getClass().getSimpleName() + " [" + e.getMessage() + "]"
                            + ": " + t.getMessage());
                }
            }
            throw new RuntimeException(e);
        }
    }

    @Override
    public void remove() {
        throw new UnsupportedOperationException("readDir(" + getPath() + ") Iterator#remove() N/A");
    }
}