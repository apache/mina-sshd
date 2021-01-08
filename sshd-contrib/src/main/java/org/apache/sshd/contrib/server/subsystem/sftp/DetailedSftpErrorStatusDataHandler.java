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

import java.nio.file.FileSystemException;
import java.util.Objects;

import org.apache.sshd.sftp.common.SftpException;
import org.apache.sshd.sftp.server.SftpErrorStatusDataHandler;
import org.apache.sshd.sftp.server.SftpSubsystemEnvironment;

/**
 * An {@link SftpErrorStatusDataHandler} implementation that returns an elaborate message string for the thrown
 * exception - thus potentially &quot;leaking&quot; information about the internal implementation and/or real paths.
 * Recommended for debugging or systems where such leakage is not considered a security risk
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DetailedSftpErrorStatusDataHandler implements SftpErrorStatusDataHandler {
    public static final DetailedSftpErrorStatusDataHandler INSTANCE = new DetailedSftpErrorStatusDataHandler();

    public DetailedSftpErrorStatusDataHandler() {
        super();
    }

    @Override
    public String resolveErrorMessage(
            SftpSubsystemEnvironment sftpSubsystem, int id, Throwable e, int subStatus, int cmd, Object... args) {
        if (e instanceof FileSystemException) {
            FileSystemException fse = (FileSystemException) e;
            String file = fse.getFile();
            String otherFile = fse.getOtherFile();
            String message = fse.getReason();
            return e.getClass().getSimpleName()
                   + "[file=" + file + "]"
                   + (Objects.equals(file, otherFile) ? "" : "[other=" + otherFile + "]")
                   + ": " + message;
        } else if (e instanceof SftpException) {
            return e.toString();
        } else {
            return "Internal " + e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }
}
