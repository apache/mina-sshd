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
import java.nio.file.CopyOption;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Map;

import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.server.SftpEventListener;
import org.slf4j.Logger;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpServerSubSystemEventListener extends ServerEventListenerHelper implements SftpEventListener {
    public SftpServerSubSystemEventListener(Logger logger) {
        super(SftpConstants.SFTP_SUBSYSTEM_NAME, logger);
    }

    @Override
    public void initialized(ServerSession session, int version) throws IOException {
        if (log.isInfoEnabled()) {
            log.info("Session {} initialized - version={}", session, version);
        }
    }

    @Override
    public void destroying(ServerSession session) throws IOException {
        if (log.isInfoEnabled()) {
            log.info("Session destroyed: {}", session);
        }
    }

    @Override
    public void created(
            ServerSession session, Path path, Map<String, ?> attrs, Throwable thrown)
            throws IOException {
        if (thrown == null) {
            if (log.isInfoEnabled()) {
                log.info("Session {} created directory {} with attributes={}", session, path, attrs);
            }
        } else {
            log.error("Failed ({}) to create directory {} in session {}: {}",
                    thrown.getClass().getSimpleName(), path, session, thrown.getMessage());
        }
    }

    @Override
    public void moved(
            ServerSession session, Path srcPath, Path dstPath, Collection<CopyOption> opts, Throwable thrown)
            throws IOException {
        if (thrown == null) {
            if (log.isInfoEnabled()) {
                log.info("Session {} moved {} to {} with options={}",
                        session, srcPath, dstPath, opts);
            }
        } else {
            log.error("Failed ({}) to move {} to {} using options={} in session {}: {}",
                    thrown.getClass().getSimpleName(), srcPath, dstPath, opts, session, thrown.getMessage());
        }
    }

    @Override
    public void removed(ServerSession session, Path path, boolean isDirectory, Throwable thrown) throws IOException {
        if (thrown == null) {
            if (log.isInfoEnabled()) {
                log.info("Session {} removed {}", session, path);
            }
        } else {
            log.error("Failed ({}) to remove {} in session {}: {}",
                    thrown.getClass().getSimpleName(), path, session, thrown.getMessage());
        }
    }
}
