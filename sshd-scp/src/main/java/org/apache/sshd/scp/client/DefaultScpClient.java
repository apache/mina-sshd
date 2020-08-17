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
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;

import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.util.MockFileSystem;
import org.apache.sshd.common.file.util.MockPath;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.scp.common.ScpFileOpener;
import org.apache.sshd.scp.common.ScpHelper;
import org.apache.sshd.scp.common.ScpTransferEventListener;
import org.apache.sshd.scp.common.helpers.DefaultScpFileOpener;
import org.apache.sshd.scp.common.helpers.ScpTimestampCommandDetails;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultScpClient extends AbstractScpClient {
    protected final ScpFileOpener opener;
    protected final ScpTransferEventListener listener;
    private final ClientSession clientSession;

    public DefaultScpClient(ClientSession clientSession) {
        this(clientSession, DefaultScpFileOpener.INSTANCE, ScpTransferEventListener.EMPTY);
    }

    public DefaultScpClient(
                            ClientSession clientSession, ScpFileOpener fileOpener, ScpTransferEventListener eventListener) {
        this.clientSession = Objects.requireNonNull(clientSession, "No client session");
        this.opener = (fileOpener == null) ? DefaultScpFileOpener.INSTANCE : fileOpener;
        this.listener = (eventListener == null) ? ScpTransferEventListener.EMPTY : eventListener;
    }

    @Override
    public ClientSession getClientSession() {
        return clientSession;
    }

    @Override
    public void download(String remote, OutputStream local) throws IOException {
        String cmd = ScpClient.createReceiveCommand(remote, Collections.emptyList());
        ClientSession session = getClientSession();
        ChannelExec channel = openCommandChannel(session, cmd);
        try (InputStream invOut = channel.getInvertedOut();
             OutputStream invIn = channel.getInvertedIn()) {
            // NOTE: we use a mock file system since we expect no invocations for it
            ScpHelper helper = new ScpHelper(session, invOut, invIn, new MockFileSystem(remote), opener, listener);
            helper.receiveFileStream(local, ScpHelper.DEFAULT_RECEIVE_BUFFER_SIZE);
            handleCommandExitStatus(cmd, channel);
        } finally {
            channel.close(false);
        }
    }

    @Override
    protected void download(String remote, FileSystem fs, Path local, Collection<Option> options) throws IOException {
        String cmd = ScpClient.createReceiveCommand(remote, options);
        ClientSession session = getClientSession();
        ChannelExec channel = openCommandChannel(session, cmd);
        try (InputStream invOut = channel.getInvertedOut();
             OutputStream invIn = channel.getInvertedIn()) {
            ScpHelper helper = new ScpHelper(session, invOut, invIn, fs, opener, listener);
            helper.receive(local,
                    options.contains(Option.Recursive),
                    options.contains(Option.TargetIsDirectory),
                    options.contains(Option.PreserveAttributes),
                    ScpHelper.DEFAULT_RECEIVE_BUFFER_SIZE);
            handleCommandExitStatus(cmd, channel);
        } finally {
            channel.close(false);
        }
    }

    @Override
    public void upload(
            InputStream local, String remote, long size, Collection<PosixFilePermission> perms, ScpTimestampCommandDetails time)
            throws IOException {
        int namePos = ValidateUtils.checkNotNullAndNotEmpty(remote, "No remote location specified").lastIndexOf('/');
        String name = (namePos < 0)
                ? remote
                : ValidateUtils.checkNotNullAndNotEmpty(remote.substring(namePos + 1), "No name value in remote=%s", remote);
        Collection<Option> options = (time != null) ? EnumSet.of(Option.PreserveAttributes) : Collections.emptySet();
        String cmd = ScpClient.createSendCommand(remote, options);
        ClientSession session = getClientSession();
        ChannelExec channel = openCommandChannel(session, cmd);
        try (InputStream invOut = channel.getInvertedOut();
             OutputStream invIn = channel.getInvertedIn()) {
            // NOTE: we use a mock file system since we expect no invocations for it
            ScpHelper helper = new ScpHelper(session, invOut, invIn, new MockFileSystem(remote), opener, listener);
            Path mockPath = new MockPath(remote);
            helper.sendStream(new DefaultScpStreamResolver(name, mockPath, perms, time, size, local, cmd),
                    options.contains(Option.PreserveAttributes), ScpHelper.DEFAULT_SEND_BUFFER_SIZE);
            handleCommandExitStatus(cmd, channel);
        } finally {
            channel.close(false);
        }
    }

    @Override
    protected <T> void runUpload(
            String remote, Collection<Option> options, Collection<T> local, AbstractScpClient.ScpOperationExecutor<T> executor)
            throws IOException {
        local = ValidateUtils.checkNotNullAndNotEmpty(local, "Invalid argument local: %s", local);
        remote = ValidateUtils.checkNotNullAndNotEmpty(remote, "Invalid argument remote: %s", remote);
        if (local.size() > 1) {
            options = addTargetIsDirectory(options);
        }

        String cmd = ScpClient.createSendCommand(remote, options);
        ClientSession session = getClientSession();
        ChannelExec channel = openCommandChannel(session, cmd);
        try {
            FactoryManager manager = session.getFactoryManager();
            FileSystemFactory factory = manager.getFileSystemFactory();
            FileSystem fs = factory.createFileSystem(session);

            try (InputStream invOut = channel.getInvertedOut();
                 OutputStream invIn = channel.getInvertedIn()) {
                ScpHelper helper = new ScpHelper(session, invOut, invIn, fs, opener, listener);
                executor.execute(helper, local, options);
            } finally {
                try {
                    fs.close();
                } catch (UnsupportedOperationException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("runUpload({}) {} => {} - failed ({}) to close file system={}: {}",
                                session, remote, local, e.getClass().getSimpleName(), fs, e.getMessage());
                    }
                }
            }
            handleCommandExitStatus(cmd, channel);
        } finally {
            channel.close(false);
        }
    }
}
