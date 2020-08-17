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
import org.apache.sshd.scp.server.ScpCommandFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpCommandTransferEventListener
        extends ServerEventListenerHelper
        implements ScpTransferEventListener {
    public ScpCommandTransferEventListener(Appendable stdout, Appendable stderr) {
        super(ScpCommandFactory.SCP_FACTORY_NAME, stdout, stderr);
    }

    @Override
    public void startFileEvent(
            Session session, FileOperation op, Path file, long length, Set<PosixFilePermission> perms)
            throws IOException {
        outputDebugMessage("startFileEvent(%s)[%s] len=%d, perms=%s: %s", session, op, length, perms, file);
    }

    @Override
    public void endFileEvent(
            Session session, FileOperation op, Path file, long length, Set<PosixFilePermission> perms, Throwable thrown)
            throws IOException {
        if (thrown != null) {
            outputErrorMessage("endFileEvent(%s)[%s] failed (%s) len=%d, perms=%s [%s]: %s",
                    session, op, thrown.getClass().getSimpleName(), length, perms, file, thrown.getMessage());
        } else {
            outputDebugMessage("endFileEvent(%s)[%s] len=%d, perms=%s: %s", session, op, length, perms, file);
        }
    }

    @Override
    public void startFolderEvent(Session session, FileOperation op, Path file, Set<PosixFilePermission> perms)
            throws IOException {
        outputDebugMessage("startFolderEvent(%s)[%s] perms=%s: %s", session, op, perms, file);
    }

    @Override
    public void endFolderEvent(
            Session session, FileOperation op, Path file, Set<PosixFilePermission> perms, Throwable thrown)
            throws IOException {
        if (thrown != null) {
            outputErrorMessage("endFolderEvent(%s)[%s] failed (%s) perms=%s [%s]: %s",
                    session, op, thrown.getClass().getSimpleName(), perms, file, thrown.getMessage());
        } else {
            outputDebugMessage("endFolderEvent(%s)[%s] lperms=%s: %s", session, op, perms, file);
        }
    }
}
