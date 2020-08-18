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

package org.apache.sshd.scp.client;

import java.io.IOException;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.scp.common.helpers.ScpReceiveDirCommandDetails;
import org.apache.sshd.scp.common.helpers.ScpReceiveFileCommandDetails;
import org.apache.sshd.scp.common.helpers.ScpTimestampCommandDetails;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ScpRemote2RemoteTransferListener {
    /**
     * Indicates start of direct file transfer
     *
     * @param  srcSession  The source {@link ClientSession}
     * @param  source      The source path
     * @param  dstSession  The destination {@link ClientSession}
     * @param  destination The destination path
     * @param  timestamp   The {@link ScpTimestampCommandDetails timestamp} of the file - may be {@code null}
     * @param  details     The {@link ScpReceiveFileCommandDetails details} of the attempted file transfer
     * @throws IOException If failed to handle the callback
     */
    void startDirectFileTransfer(
            ClientSession srcSession, String source,
            ClientSession dstSession, String destination,
            ScpTimestampCommandDetails timestamp, ScpReceiveFileCommandDetails details)
            throws IOException;

    /**
     * Indicates end of direct file transfer
     *
     * @param  srcSession  The source {@link ClientSession}
     * @param  source      The source path
     * @param  dstSession  The destination {@link ClientSession}
     * @param  destination The destination path
     * @param  timestamp   The {@link ScpTimestampCommandDetails timestamp} of the file - may be {@code null}
     * @param  details     The {@link ScpReceiveFileCommandDetails details} of the attempted file transfer
     * @param  xferSize    Number of successfully transfered bytes - zero if <tt>thrown</tt> not {@code null}
     * @param  thrown      Error thrown during transfer attempt - {@code null} if successful
     * @throws IOException If failed to handle the callback
     */
    void endDirectFileTransfer(
            ClientSession srcSession, String source,
            ClientSession dstSession, String destination,
            ScpTimestampCommandDetails timestamp, ScpReceiveFileCommandDetails details,
            long xferSize, Throwable thrown)
            throws IOException;

    /**
     * Indicates start of direct directory transfer
     *
     * @param  srcSession  The source {@link ClientSession}
     * @param  source      The source path
     * @param  dstSession  The destination {@link ClientSession}
     * @param  destination The destination path
     * @param  timestamp   The {@link ScpTimestampCommandDetails timestamp} of the directory - may be {@code null}
     * @param  details     The {@link ScpReceiveDirCommandDetails details} of the attempted directory transfer
     * @throws IOException If failed to handle the callback
     */
    void startDirectDirectoryTransfer(
            ClientSession srcSession, String source,
            ClientSession dstSession, String destination,
            ScpTimestampCommandDetails timestamp, ScpReceiveDirCommandDetails details)
            throws IOException;

    /**
     * Indicates end of direct file transfer
     *
     * @param  srcSession  The source {@link ClientSession}
     * @param  source      The source path
     * @param  dstSession  The destination {@link ClientSession}
     * @param  destination The destination path
     * @param  timestamp   The {@link ScpTimestampCommandDetails timestamp} of the directory - may be {@code null}
     * @param  details     The {@link ScpReceiveDirCommandDetails details} of the attempted directory transfer
     * @param  thrown      Error thrown during transfer attempt - {@code null} if successful
     * @throws IOException If failed to handle the callback
     */
    void endDirectDirectoryTransfer(
            ClientSession srcSession, String source,
            ClientSession dstSession, String destination,
            ScpTimestampCommandDetails timestamp, ScpReceiveDirCommandDetails details,
            Throwable thrown)
            throws IOException;
}
