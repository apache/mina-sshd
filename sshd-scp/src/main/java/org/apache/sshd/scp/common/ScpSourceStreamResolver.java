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
import java.io.InputStream;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Collection;
import java.util.Set;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.scp.common.helpers.ScpTimestampCommandDetails;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ScpSourceStreamResolver {
    /**
     * @return             The uploaded file name
     * @throws IOException If failed to resolve the name
     */
    String getFileName() throws IOException;

    /**
     * @return The {@link Path} to use when invoking the {@link ScpTransferEventListener}
     */
    Path getEventListenerFilePath();

    /**
     * @return             The permissions to be used for uploading a file
     * @throws IOException If failed to generate the required permissions
     */
    Collection<PosixFilePermission> getPermissions() throws IOException;

    /**
     * @return             The {@link ScpTimestampCommandDetails} to use for uploading the file if {@code null} then no
     *                     need to send this information
     * @throws IOException If failed to generate the required data
     */
    ScpTimestampCommandDetails getTimestamp() throws IOException;

    /**
     * @return             An estimated size of the expected number of bytes to be uploaded. If non-positive then
     *                     assumed to be unknown.
     * @throws IOException If failed to generate an estimate
     */
    long getSize() throws IOException;

    /**
     * @param  session     The {@link Session} through which file is transmitted
     * @param  fileSize    The expected transfer byte count
     * @param  permissions The requested file permissions
     * @param  options     The {@link OpenOption}s may be {@code null}/empty
     * @return             The {@link InputStream} containing the data to be uploaded
     * @throws IOException If failed to create the stream
     */
    InputStream resolveSourceStream(
            Session session, long fileSize, Set<PosixFilePermission> permissions, OpenOption... options)
            throws IOException;

    /**
     * Called when the stream obtained from {@link #resolveSourceStream(Session, long, Set, OpenOption...)
     * resolveSourceStream} is no longer needed since since file copy was completed successfully.
     *
     * @param  session     The {@link Session} through which file is transmitted
     * @param  fileSize    The expected transfer byte count
     * @param  permissions The requested file permissions
     * @param  stream      The {@link InputStream} to close
     * @throws IOException If failed to close the stream - <B>Note:</B> stream will be closed regardless of whether this
     *                     method throws an exception or not.
     */
    default void closeSourceStream(
            Session session, long fileSize, Set<PosixFilePermission> permissions, InputStream stream)
            throws IOException {
        if (stream != null) {
            stream.close();
        }
    }
}
