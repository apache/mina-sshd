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
package org.apache.sshd.client.scp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Collection;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionHolder;
import org.apache.sshd.common.scp.ScpTimestamp;
import org.apache.sshd.common.session.SessionHolder;

/**
 */
public interface ScpClient extends SessionHolder<ClientSession>, ClientSessionHolder {

    enum Option {
        Recursive,
        PreserveAttributes,
        TargetIsDirectory
    }

    /**
     * Configurable value of the {@link org.apache.sshd.common.FactoryManager}
     * for controlling the wait timeout for opening a channel for an SCP command
     * in milliseconds. If not specified, then {@link #DEFAULT_EXEC_CHANNEL_OPEN_TIMEOUT}
     * value is used
     */
    String SCP_EXEC_CHANNEL_OPEN_TIMEOUT = "scp-exec-channel-open-timeout";
    long DEFAULT_EXEC_CHANNEL_OPEN_TIMEOUT = TimeUnit.SECONDS.toMillis(30L);

    void download(String remote, String local, Option... options) throws IOException;

    void download(String remote, String local, Collection<Option> options) throws IOException;

    void download(String remote, Path local, Option... options) throws IOException;

    void download(String remote, Path local, Collection<Option> options) throws IOException;

    // NOTE: the remote location MUST be a file or an exception is generated
    void download(String remote, OutputStream local) throws IOException;

    byte[] downloadBytes(String remote) throws IOException;

    void download(String[] remote, String local, Option... options) throws IOException;

    void download(String[] remote, String local, Collection<Option> options) throws IOException;

    void download(String[] remote, Path local, Option... options) throws IOException;

    void download(String[] remote, Path local, Collection<Option> options) throws IOException;

    void upload(String local, String remote, Option... options) throws IOException;

    void upload(String local, String remote, Collection<Option> options) throws IOException;

    void upload(Path local, String remote, Option... options) throws IOException;

    void upload(Path local, String remote, Collection<Option> options) throws IOException;

    void upload(String[] local, String remote, Option... options) throws IOException;

    void upload(String[] local, String remote, Collection<Option> options) throws IOException;

    void upload(Path[] local, String remote, Option... options) throws IOException;

    void upload(Path[] local, String remote, Collection<Option> options) throws IOException;

    // NOTE: due to SCP command limitations, the amount of data to be uploaded must be known a-priori
    // To upload a dynamic amount of data use SFTP
    void upload(byte[] data, String remote, Collection<PosixFilePermission> perms, ScpTimestamp time) throws IOException;

    void upload(byte[] data, int offset, int len, String remote, Collection<PosixFilePermission> perms, ScpTimestamp time) throws IOException;

    void upload(InputStream local, String remote, long size, Collection<PosixFilePermission> perms, ScpTimestamp time) throws IOException;
}
