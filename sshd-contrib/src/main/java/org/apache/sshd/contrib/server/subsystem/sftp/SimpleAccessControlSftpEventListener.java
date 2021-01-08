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

package org.apache.sshd.contrib.server.subsystem.sftp;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.CopyOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Collection;
import java.util.Map;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.sftp.server.AbstractSftpEventListenerAdapter;
import org.apache.sshd.sftp.server.DirectoryHandle;
import org.apache.sshd.sftp.server.FileHandle;
import org.apache.sshd.sftp.server.Handle;

/**
 * Provides a simple access control by making a distinction between methods that provide information - including reading
 * data - and those that modify it
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class SimpleAccessControlSftpEventListener extends AbstractSftpEventListenerAdapter {
    public static final SimpleAccessControlSftpEventListener READ_ONLY_ACCESSOR = new SimpleAccessControlSftpEventListener() {
        @Override
        protected boolean isAccessAllowed(ServerSession session, String remoteHandle, Path localPath)
                throws IOException {
            return true;
        }

        @Override
        protected boolean isModificationAllowed(ServerSession session, String remoteHandle, Path localPath)
                throws IOException {
            return false;
        }
    };

    protected SimpleAccessControlSftpEventListener() {
        super();
    }

    @Override
    public void opening(ServerSession session, String remoteHandle, Handle localHandle)
            throws IOException {
        super.opening(session, remoteHandle, localHandle);
        if (localHandle instanceof DirectoryHandle) {
            if (!isAccessAllowed(session, remoteHandle, localHandle)) {
                throw new AccessDeniedException(remoteHandle);
            }
        } else {
            Collection<StandardOpenOption> options = ((FileHandle) localHandle).getOpenOptions();
            if (GenericUtils.containsAny(options, IoUtils.WRITEABLE_OPEN_OPTIONS)) {
                if (!isModificationAllowed(session, remoteHandle, localHandle.getFile())) {
                    throw new AccessDeniedException(remoteHandle);
                }
            } else {
                if (!isAccessAllowed(session, remoteHandle, localHandle)) {
                    throw new AccessDeniedException(remoteHandle);
                }
            }
        }
    }

    @Override
    public void readEntries(ServerSession session, String remoteHandle, DirectoryHandle localHandle, Map<String, Path> entries)
            throws IOException {
        super.readEntries(session, remoteHandle, localHandle, entries);
        if (!isAccessAllowed(session, remoteHandle, localHandle)) {
            throw new AccessDeniedException(remoteHandle);
        }
    }

    @Override
    public void reading(
            ServerSession session, String remoteHandle, FileHandle localHandle, long offset, byte[] data,
            int dataOffset, int dataLen)
            throws IOException {
        super.reading(session, remoteHandle, localHandle, offset, data, dataOffset, dataLen);
        if (!isAccessAllowed(session, remoteHandle, localHandle)) {
            throw new AccessDeniedException(remoteHandle);
        }
    }

    /**
     * @param  session      The {@link ServerSession} throw which the request was made
     * @param  remoteHandle The remote handle value
     * @param  localHandle  The local handle
     * @return              {@code true} if allowed to access the handle
     * @throws IOException  If failed to handle the call
     */
    protected boolean isAccessAllowed(ServerSession session, String remoteHandle, Handle localHandle) throws IOException {
        return isAccessAllowed(session, remoteHandle, localHandle.getFile());
    }

    /**
     * @param  session      The {@link ServerSession} throw which the request was made
     * @param  remoteHandle The remote handle value
     * @param  localPath    The local {@link Path}
     * @return              {@code true} if allowed to access the path
     * @throws IOException  If failed to handle the call
     */
    protected abstract boolean isAccessAllowed(ServerSession session, String remoteHandle, Path localPath) throws IOException;

    @Override
    public void writing(
            ServerSession session, String remoteHandle, FileHandle localHandle, long offset, byte[] data,
            int dataOffset, int dataLen)
            throws IOException {
        super.writing(session, remoteHandle, localHandle, offset, data, dataOffset, dataLen);
        if (!isModificationAllowed(session, remoteHandle, localHandle.getFile())) {
            throw new AccessDeniedException(remoteHandle);
        }
    }

    @Override
    public void blocking(ServerSession session, String remoteHandle, FileHandle localHandle, long offset, long length, int mask)
            throws IOException {
        super.blocking(session, remoteHandle, localHandle, offset, length, mask);
        if (!isModificationAllowed(session, remoteHandle, localHandle.getFile())) {
            throw new AccessDeniedException(remoteHandle);
        }
    }

    @Override
    public void unblocking(ServerSession session, String remoteHandle, FileHandle localHandle, long offset, long length)
            throws IOException {
        super.unblocking(session, remoteHandle, localHandle, offset, length);
        if (!isModificationAllowed(session, remoteHandle, localHandle.getFile())) {
            throw new AccessDeniedException(remoteHandle);
        }
    }

    @Override
    public void creating(ServerSession session, Path path, Map<String, ?> attrs) throws IOException {
        super.creating(session, path, attrs);
        if (!isModificationAllowed(session, path.toString(), path)) {
            throw new AccessDeniedException(path.toString());
        }
    }

    @Override
    public void moving(ServerSession session, Path srcPath, Path dstPath, Collection<CopyOption> opts)
            throws IOException {
        super.moving(session, srcPath, dstPath, opts);
        if (!isModificationAllowed(session, srcPath.toString(), srcPath)) {
            throw new AccessDeniedException(srcPath.toString());
        }
    }

    @Override
    public void removing(ServerSession session, Path path, boolean isDirectory) throws IOException {
        super.removing(session, path, isDirectory);
        if (!isModificationAllowed(session, path.toString(), path)) {
            throw new AccessDeniedException(path.toString());
        }
    }

    @Override
    public void removed(ServerSession session, Path path, boolean isDirectory, Throwable thrown) throws IOException {
        super.removed(session, path, isDirectory, thrown);
        if (!isModificationAllowed(session, path.toString(), path)) {
            throw new AccessDeniedException(path.toString());
        }
    }

    @Override
    public void linking(ServerSession session, Path source, Path target, boolean symLink) throws IOException {
        super.linking(session, source, target, symLink);
        if (!isModificationAllowed(session, source.toString(), source)) {
            throw new AccessDeniedException(source.toString());
        }
    }

    @Override
    public void modifyingAttributes(ServerSession session, Path path, Map<String, ?> attrs) throws IOException {
        super.modifyingAttributes(session, path, attrs);
        if (!isModificationAllowed(session, path.toString(), path)) {
            throw new AccessDeniedException(path.toString());
        }
    }

    /**
     * @param  session      The {@link ServerSession} throw which the request was made
     * @param  remoteHandle The remote handle value
     * @param  localPath    The local {@link Path}
     * @return              {@code true} if allowed to modify the path
     * @throws IOException  If failed to handle the call
     */
    protected abstract boolean isModificationAllowed(ServerSession session, String remoteHandle, Path localPath)
            throws IOException;
}
