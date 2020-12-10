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

package org.apache.sshd.cli.server.helper;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.scp.common.ScpTransferEventListener;
import org.apache.sshd.scp.common.helpers.ScpAckInfo;
import org.apache.sshd.scp.server.ScpCommandFactory;
import org.slf4j.Logger;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpCommandTransferEventListener
        extends ServerEventListenerHelper
        implements ScpTransferEventListener {
    public ScpCommandTransferEventListener(Logger logger) {
        super(ScpCommandFactory.SCP_FACTORY_NAME, logger);
    }

    @Override
    public void startFileEvent(
            Session session, FileOperation op, Path file, long length, Set<PosixFilePermission> perms)
            throws IOException {
        if (log.isInfoEnabled()) {
            log.info("startFileEvent({})[{}] len={}, perms={}: {}", session, op, length, perms, file);
        }
    }

    @Override
    public void endFileEvent(
            Session session, FileOperation op, Path file, long length, Set<PosixFilePermission> perms, Throwable thrown)
            throws IOException {
        if (thrown != null) {
            log.error("endFileEvent({})[{}] failed ({}) len={}, perms={} [{}]: {}",
                    session, op, thrown.getClass().getSimpleName(), length, perms, file, thrown.getMessage());
        } else if (log.isInfoEnabled()) {
            log.info("endFileEvent({})[{}] len={}, perms={}: {}", session, op, length, perms, file);
        }
    }

    @Override
    public void startFolderEvent(Session session, FileOperation op, Path file, Set<PosixFilePermission> perms)
            throws IOException {
        if (log.isInfoEnabled()) {
            log.info("startFolderEvent({})[{}] perms={}: {}", session, op, perms, file);
        }
    }

    @Override
    public void endFolderEvent(
            Session session, FileOperation op, Path file, Set<PosixFilePermission> perms, Throwable thrown)
            throws IOException {
        if (thrown != null) {
            log.error("endFolderEvent({})[{}] failed ({}) perms={} [{}]: {}",
                    session, op, thrown.getClass().getSimpleName(), perms, file, thrown.getMessage());
        } else if (log.isInfoEnabled()) {
            log.info("endFolderEvent({})[{}] perms={}: {}", session, op, perms, file);
        }
    }

    @Override
    public void handleFileEventAckInfo(
            Session session, FileOperation op, Path file, long length,
            Set<PosixFilePermission> perms, ScpAckInfo ackInfo)
            throws IOException {
        if (log.isInfoEnabled()) {
            log.info("handleFileEventAckInfo({})[{}] perms={}, length={}, ACK={}: {}",
                    session, op, perms, length, ackInfo, file);
        }
    }
}
