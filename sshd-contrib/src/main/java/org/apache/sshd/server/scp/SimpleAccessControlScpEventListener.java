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

package org.apache.sshd.server.scp;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

import org.apache.sshd.common.scp.AbstractScpTransferEventListenerAdapter;

/**
 * Provides a simple access control by making a distinction between methods
 * that upload data and ones that download it
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class SimpleAccessControlScpEventListener extends AbstractScpTransferEventListenerAdapter {
    public static final SimpleAccessControlScpEventListener READ_ONLY_ACCESSOR =
        new SimpleAccessControlScpEventListener() {
            @Override
            protected boolean isFileUploadAllowed(Path path) throws IOException {
                return false;
            }

            @Override
            protected boolean isFileDownloadAllowed(Path path) throws IOException {
                return true;
            }
    };

    protected SimpleAccessControlScpEventListener() {
        super();
    }

    @Override
    public void startFileEvent(FileOperation op, Path file, long length, Set<PosixFilePermission> perms)
            throws IOException {
        super.startFileEvent(op, file, length, perms);
        switch(op) {
            case SEND:
                if (!isFileDownloadAllowed(file)) {
                    throw new AccessDeniedException(file.toString());
                }
                break;

            case RECEIVE:
                if (!isFileUploadAllowed(file)) {
                    throw new AccessDeniedException(file.toString());
                }
                break;
            default:
                throw new UnsupportedOperationException("Unknown file operation: " + op);
        }
    }

    @Override
    public void startFolderEvent(FileOperation op, Path file, Set<PosixFilePermission> perms) throws IOException {
        super.startFolderEvent(op, file, perms);
        switch(op) {
            case SEND:
                if (!isFileDownloadAllowed(file)) {
                    throw new AccessDeniedException(file.toString());
                }
                break;

            case RECEIVE:
                if (!isFileUploadAllowed(file)) {
                    throw new AccessDeniedException(file.toString());
                }
                break;
            default:
                throw new UnsupportedOperationException("Unknown file operation: " + op);
        }
    }

    /**
     * @param path The local file/folder path
     * @return {@code true} if client is allowed to read from the specified local path
     * @throws IOException If failed to handle the call
     */
    protected abstract boolean isFileDownloadAllowed(Path path) throws IOException;

    /**
     * @param path The local file/folder path
     * @return {@code true} if client is allowed to write to the specified local path
     * @throws IOException If failed to handle the call
     */
    protected abstract boolean isFileUploadAllowed(Path path) throws IOException;
}
