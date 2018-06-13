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

package org.apache.sshd.common.scp;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

import org.apache.sshd.common.util.SshdEventListener;

/**
 * Can be registered in order to receive events about SCP transfers
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ScpTransferEventListener extends SshdEventListener {
    enum FileOperation {
        SEND,
        RECEIVE
    }

    /**
     * An &quot;empty&quot; implementation to be used instead of {@code null}s
     */
    ScpTransferEventListener EMPTY = new ScpTransferEventListener() {
        @Override
        public String toString() {
            return "EMPTY";
        }
    };

    /**
     * @param op     The {@link FileOperation}
     * @param file   The <U>local</U> referenced file {@link Path}
     * @param length Size (in bytes) of transferred data
     * @param perms  A {@link Set} of {@link PosixFilePermission}s to be applied
     *               once transfer is complete
     * @throws IOException If failed to handle the event
     */
    default void startFileEvent(FileOperation op, Path file, long length, Set<PosixFilePermission> perms) throws IOException {
        // ignored
    }

    /**
     * @param op     The {@link FileOperation}
     * @param file   The <U>local</U> referenced file {@link Path}
     * @param length Size (in bytes) of transferred data
     * @param perms  A {@link Set} of {@link PosixFilePermission}s to be applied
     *               once transfer is complete
     * @param thrown The result of the operation attempt - if {@code null} then
     *               reception was successful
     * @throws IOException If failed to handle the event
     */
    default void endFileEvent(FileOperation op, Path file, long length, Set<PosixFilePermission> perms, Throwable thrown)
            throws IOException {
                // ignored
    }

    /**
     * @param op    The {@link FileOperation}
     * @param file  The <U>local</U> referenced folder {@link Path}
     * @param perms A {@link Set} of {@link PosixFilePermission}s to be applied
     *              once transfer is complete
     * @throws IOException If failed to handle the event
     */
    default void startFolderEvent(FileOperation op, Path file, Set<PosixFilePermission> perms) throws IOException {
        // ignored
    }

    /**
     * @param op     The {@link FileOperation}
     * @param file   The <U>local</U> referenced file {@link Path}
     * @param perms  A {@link Set} of {@link PosixFilePermission}s to be applied
     *               once transfer is complete
     * @param thrown The result of the operation attempt - if {@code null} then
     *               reception was successful
     * @throws IOException If failed to handle the event
     */
    default void endFolderEvent(FileOperation op, Path file, Set<PosixFilePermission> perms, Throwable thrown)
            throws IOException {
        // ignored
    }

    static <L extends ScpTransferEventListener> L validateListener(L listener) {
        return SshdEventListener.validateListener(listener, ScpTransferEventListener.class.getSimpleName());
    }
}
