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

package org.apache.sshd.scp.common;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.SshdEventListener;
import org.apache.sshd.scp.common.helpers.ScpAckInfo;

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
     * @param  session     The client/server {@link Session} through which the transfer is being executed
     * @param  op          The {@link FileOperation}
     * @param  file        The <U>local</U> referenced file {@link Path}
     * @param  length      Size (in bytes) of transferred data
     * @param  perms       A {@link Set} of {@link PosixFilePermission}s to be applied once transfer is complete
     * @throws IOException If failed to handle the event
     */
    default void startFileEvent(
            Session session, FileOperation op, Path file, long length, Set<PosixFilePermission> perms)
            throws IOException {
        // ignored
    }

    /**
     * @param  session     The client/server {@link Session} through which the transfer is being executed
     * @param  op          The {@link FileOperation}
     * @param  file        The <U>local</U> referenced file {@link Path}
     * @param  length      Size (in bytes) of transferred data
     * @param  perms       A {@link Set} of {@link PosixFilePermission}s to be applied once transfer is complete
     * @param  thrown      The result of the operation attempt - if {@code null} then reception was successful
     * @throws IOException If failed to handle the event
     */
    default void endFileEvent(
            Session session, FileOperation op, Path file, long length, Set<PosixFilePermission> perms, Throwable thrown)
            throws IOException {
        // ignored
    }

    /**
     * Called after {@link #endFileEvent(Session, FileOperation, Path, long, Set, Throwable)} if no exception was thrown
     * and the peer's ACK was successfully read
     *
     * @param  session     The client/server {@link Session} through which the transfer is being executed
     * @param  op          The {@link FileOperation}
     * @param  file        The <U>local</U> referenced file {@link Path}
     * @param  length      Size (in bytes) of transferred data
     * @param  perms       A {@link Set} of {@link PosixFilePermission}s to be applied once transfer is complete
     * @param  ackInfo     The {@link ScpAckInfo} received after a file transfer - <U>before</U> validating it
     * @throws IOException If failed to handle the event
     */
    default void handleFileEventAckInfo(
            Session session, FileOperation op, Path file, long length, Set<PosixFilePermission> perms, ScpAckInfo ackInfo)
            throws IOException {
        // ignored
    }

    /**
     * @param  session     The client/server {@link Session} through which the transfer is being executed
     * @param  op          The {@link FileOperation}
     * @param  file        The <U>local</U> referenced folder {@link Path}
     * @param  perms       A {@link Set} of {@link PosixFilePermission}s to be applied once transfer is complete
     * @throws IOException If failed to handle the event
     */
    default void startFolderEvent(
            Session session, FileOperation op, Path file, Set<PosixFilePermission> perms)
            throws IOException {
        // ignored
    }

    /**
     * @param  session     The client/server {@link Session} through which the transfer is being executed
     * @param  op          The {@link FileOperation}
     * @param  file        The <U>local</U> referenced file {@link Path}
     * @param  perms       A {@link Set} of {@link PosixFilePermission}s to be applied once transfer is complete
     * @param  thrown      The result of the operation attempt - if {@code null} then reception was successful
     * @throws IOException If failed to handle the event
     */
    default void endFolderEvent(
            Session session, FileOperation op, Path file, Set<PosixFilePermission> perms, Throwable thrown)
            throws IOException {
        // ignored
    }

    static <L extends ScpTransferEventListener> L validateListener(L listener) {
        return SshdEventListener.validateListener(listener, ScpTransferEventListener.class.getSimpleName());
    }
}
