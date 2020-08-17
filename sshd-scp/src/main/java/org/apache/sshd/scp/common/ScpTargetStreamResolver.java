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
import java.io.OutputStream;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.scp.common.helpers.ScpTimestampCommandDetails;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ScpTargetStreamResolver {
    /**
     * Called when receiving a file in order to obtain an output stream for the incoming data
     *
     * @param  session     The associated {@link Session}
     * @param  name        File name as received from remote site
     * @param  length      Number of bytes expected to receive
     * @param  perms       The {@link Set} of {@link PosixFilePermission} expected
     * @param  options     The {@link OpenOption}s to use - may be {@code null}/empty
     * @return             The {@link OutputStream} to write the incoming data
     * @throws IOException If failed to create the stream
     */
    OutputStream resolveTargetStream(
            Session session, String name, long length, Set<PosixFilePermission> perms, OpenOption... options)
            throws IOException;

    /**
     * Called when target stream received from {@link #resolveTargetStream(Session, String, long, Set, OpenOption...)
     * resolveTargetStream} call is no longer needed since copy is successfully completed.
     *
     * @param  session     The associated {@link Session}
     * @param  name        File name as received from remote site
     * @param  length      Number of bytes expected to receive
     * @param  perms       The {@link Set} of {@link PosixFilePermission} expected
     * @param  stream      The {@link OutputStream} to close
     * @throws IOException If failed to close the stream - <B>Note:</B> stream will be closed regardless of whether this
     *                     method throws an exception or not.
     */
    default void closeTargetStream(
            Session session, String name, long length, Set<PosixFilePermission> perms, OutputStream stream)
            throws IOException {
        if (stream != null) {
            stream.close();
        }
    }

    /**
     * @return The {@link Path} to use when invoking the {@link ScpTransferEventListener}
     */
    Path getEventListenerFilePath();

    /**
     * Called after successful reception of the data (and after closing the stream)
     *
     * @param  name        File name as received from remote site
     * @param  preserve    If {@code true} then the resolver should attempt to preserve the specified permissions and
     *                     timestamp
     * @param  perms       The {@link Set} of {@link PosixFilePermission} expected
     * @param  time        If not {@code null} then the required timestamp(s) on the incoming data
     * @throws IOException If failed to post-process the incoming data
     */
    void postProcessReceivedData(
            String name, boolean preserve, Set<PosixFilePermission> perms, ScpTimestampCommandDetails time)
            throws IOException;
}
