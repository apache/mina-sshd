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

import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EventListener;
import java.util.Set;

/**
 * Can be registered in order to receive events about SCP transfers
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ScpTransferEventListener extends EventListener {

    enum FileOperation {
        SEND,
        RECEIVE
    }

    /**
     * An &quot;empty&quot; implementation to be used instead of {@code null}s
     */
    ScpTransferEventListener EMPTY = new ScpTransferEventListener() {
        // TODO in JDK 8.0 implement all methods as default with empty body in the interface itself

        @Override
        public void startFileEvent(FileOperation op, Path file, long length, Set<PosixFilePermission> perms) {
            // ignored
        }

        @Override
        public void endFileEvent(FileOperation op, Path file, long length, Set<PosixFilePermission> perms, Throwable thrown) {
            // ignored
        }

        @Override
        public void startFolderEvent(FileOperation op, Path file, Set<PosixFilePermission> perms) {
            // ignored
        }

        @Override
        public void endFolderEvent(FileOperation op, Path file, Set<PosixFilePermission> perms, Throwable thrown) {
            // ignored
        }
    };

    /**
     * @param op     The {@link FileOperation}
     * @param file   The <U>local</U> referenced file {@link Path}
     * @param length Size (in bytes) of transfered data
     * @param perms  A {@link Set} of {@link PosixFilePermission}s to be applied
     *               once transfer is complete
     */
    void startFileEvent(FileOperation op, Path file, long length, Set<PosixFilePermission> perms);

    /**
     * @param op     The {@link FileOperation}
     * @param file   The <U>local</U> referenced file {@link Path}
     * @param length Size (in bytes) of transfered data
     * @param perms  A {@link Set} of {@link PosixFilePermission}s to be applied
     *               once transfer is complete
     * @param thrown The result of the operation attempt - if {@code null} then
     *               reception was successful
     */
    void endFileEvent(FileOperation op, Path file, long length, Set<PosixFilePermission> perms, Throwable thrown);

    /**
     * @param op    The {@link FileOperation}
     * @param file  The <U>local</U> referenced folder {@link Path}
     * @param perms A {@link Set} of {@link PosixFilePermission}s to be applied
     *              once transfer is complete
     */
    void startFolderEvent(FileOperation op, Path file, Set<PosixFilePermission> perms);

    /**
     * @param op     The {@link FileOperation}
     * @param file   The <U>local</U> referenced file {@link Path}
     * @param perms  A {@link Set} of {@link PosixFilePermission}s to be applied
     *               once transfer is complete
     * @param thrown The result of the operation attempt - if {@code null} then
     *               reception was successful
     */
    void endFolderEvent(FileOperation op, Path file, Set<PosixFilePermission> perms, Throwable thrown);

}
