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
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * A no-op implementation of {@link ScpTransferEventListener} for those who wish to implement only a small number of
 * methods. By default, all non-overridden methods simply log at TRACE level their invocation parameters
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractScpTransferEventListenerAdapter
        extends AbstractLoggingBean
        implements ScpTransferEventListener {
    protected AbstractScpTransferEventListenerAdapter() {
        super();
    }

    @Override
    public void startFileEvent(
            Session session, FileOperation op, Path file, long length, Set<PosixFilePermission> perms)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("startFileEvent({})[{}] - length={}, permissions={}, file={}", session, op, length, perms, file);
        }
    }

    @Override
    public void endFileEvent(
            Session session, FileOperation op, Path file, long length, Set<PosixFilePermission> perms, Throwable thrown)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("endFileEvent({})[{}] - length={}, permissions={}, file={} - {}",
                    session, op, length, perms, file,
                    (thrown == null) ? "OK" : thrown.getClass().getSimpleName() + ": " + thrown.getMessage());
        }
    }

    @Override
    public void startFolderEvent(
            Session session, FileOperation op, Path file, Set<PosixFilePermission> perms)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("startFolderEvent({})[{}] - permissions={}, file={}", session, op, perms, file);
        }
    }

    @Override
    public void endFolderEvent(
            Session session, FileOperation op, Path file, Set<PosixFilePermission> perms, Throwable thrown)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("endFolderEvent({})[{}] - permissions={}, file={} - {}",
                    session, op, perms, file,
                    (thrown == null) ? "OK" : thrown.getClass().getSimpleName() + ": " + thrown.getMessage());
        }
    }
}
