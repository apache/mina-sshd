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

package org.apache.sshd.sftp.server;

import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.session.ServerSessionHolder;
import org.apache.sshd.sftp.common.SftpConstants;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SftpSubsystemEnvironment extends SessionHolder<ServerSession>, ServerSessionHolder {

    int LOWER_SFTP_IMPL = SftpConstants.SFTP_V3; // Working implementation from v3

    int HIGHER_SFTP_IMPL = SftpConstants.SFTP_V6; // .. up to and including

    List<Integer> SUPPORTED_SFTP_VERSIONS = Collections.unmodifiableList(
            IntStream.rangeClosed(LOWER_SFTP_IMPL, HIGHER_SFTP_IMPL)
                    .boxed()
                    .collect(Collectors.toList()));

    String ALL_SFTP_IMPL = GenericUtils.join(SUPPORTED_SFTP_VERSIONS, ',');

    @Override
    default ServerSession getSession() {
        return getServerSession();
    }

    /**
     * @return The negotiated version
     */
    int getVersion();

    /**
     * @return The {@link SftpFileSystemAccessor} used to access effective server-side paths
     */
    SftpFileSystemAccessor getFileSystemAccessor();

    /**
     * @return The selected behavior in case some unsupported attributes are requested
     */
    UnsupportedAttributePolicy getUnsupportedAttributePolicy();

    /**
     * @return The default root directory used to resolve relative paths - a.k.a. the {@code chroot} location
     */
    Path getDefaultDirectory();
}
