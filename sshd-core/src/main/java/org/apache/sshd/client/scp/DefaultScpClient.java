/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.client.scp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;

import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.util.MockFileSystem;
import org.apache.sshd.common.file.util.MockPath;
import org.apache.sshd.common.scp.ScpHelper;
import org.apache.sshd.common.scp.ScpSourceStreamResolver;
import org.apache.sshd.common.scp.ScpTimestamp;
import org.apache.sshd.common.scp.ScpTransferEventListener;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultScpClient extends AbstractScpClient {

    private final ClientSession clientSession;
    private final ScpTransferEventListener listener;

    public DefaultScpClient(ClientSession clientSession) {
        this(clientSession, ScpTransferEventListener.EMPTY);
    }

    public DefaultScpClient(ClientSession clientSession, ScpTransferEventListener eventListener) {
        this.clientSession = clientSession;
        this.listener = (eventListener == null) ? ScpTransferEventListener.EMPTY : eventListener;
    }

    @Override
    public void download(String remote, String local, Collection<Option> options) throws IOException {
        local = ValidateUtils.checkNotNullAndNotEmpty(local, "Invalid argument local: %s", local);

        FactoryManager manager = clientSession.getFactoryManager();
        FileSystemFactory factory = manager.getFileSystemFactory();
        FileSystem fs = factory.createFileSystem(clientSession);
        try {
            download(remote, fs, fs.getPath(local), options);
        } finally {
            try {
                fs.close();
            } catch (UnsupportedOperationException e) {
                // Ignore
            }
        }
    }

    @Override
    public void download(String remote, OutputStream local) throws IOException {
        String cmd = createReceiveCommand(remote, Collections.<Option>emptyList());
        ChannelExec channel = clientSession.createExecChannel(cmd);
        try {
            channel.open().await(); // TODO use verify + configurable timeout

            // NOTE: we use a mock file system since we expect no invocations for it
            ScpHelper helper = new ScpHelper(channel.getInvertedOut(), channel.getInvertedIn(), new MockFileSystem(remote), listener);
            helper.receiveFileStream(local, ScpHelper.DEFAULT_RECEIVE_BUFFER_SIZE);
        } finally {
            channel.close(false);
        }
    }

    @Override
    protected void download(String remote, FileSystem fs, Path local, Collection<Option> options) throws IOException {
        String cmd = createReceiveCommand(remote, options);
        ChannelExec channel = clientSession.createExecChannel(cmd);
        try {
            channel.open().await(); // TODO use verify + configurable timeout

            ScpHelper helper = new ScpHelper(channel.getInvertedOut(), channel.getInvertedIn(), fs, listener);
            helper.receive(local,
                           options.contains(Option.Recursive),
                           options.contains(Option.TargetIsDirectory),
                           options.contains(Option.PreserveAttributes),
                           ScpHelper.DEFAULT_RECEIVE_BUFFER_SIZE);
        } finally {
            channel.close(false);
        }
    }

    @Override
    public void upload(final InputStream local, final String remote, final long size, final Collection<PosixFilePermission> perms, final ScpTimestamp time) throws IOException {
        int namePos = ValidateUtils.checkNotNullAndNotEmpty(remote, "No remote location specified", GenericUtils.EMPTY_OBJECT_ARRAY).lastIndexOf('/');
        final String name = (namePos < 0)
                          ? remote
                          : ValidateUtils.checkNotNullAndNotEmpty(remote.substring(namePos + 1), "No name value in remote=%s", remote)
                          ;
        final String cmd = createSendCommand(remote, (time != null) ? EnumSet.of(Option.PreserveAttributes) : Collections.<Option>emptySet());
        ChannelExec channel = clientSession.createExecChannel(cmd);
        channel.open().await();   // TODO use verify + configurable timeout

        try {
            ScpHelper helper = new ScpHelper(channel.getInvertedOut(), channel.getInvertedIn(), new MockFileSystem(remote), listener);
            final Path mockPath = new MockPath(remote);
            helper.sendStream(new ScpSourceStreamResolver() {
                                    @Override
                                    public String getFileName() throws IOException {
                                        return name;
                                    }
                    
                                    @Override
                                    public Path getEventListenerFilePath() {
                                        return mockPath;
                                    }
                    
                                    @Override
                                    public Collection<PosixFilePermission> getPermissions() throws IOException {
                                        return perms;
                                    }
                    
                                    @Override
                                    public ScpTimestamp getTimestamp() throws IOException {
                                        return time;
                                    }
                    
                                    @Override
                                    public long getSize() throws IOException {
                                        return size;
                                    }
                    
                                    @Override
                                    public InputStream resolveSourceStream() throws IOException {
                                        return local;
                                    }
                                    
                                    @Override
                                    public String toString() {
                                        return cmd;
                                    }
                              },
                              (time != null), ScpHelper.DEFAULT_SEND_BUFFER_SIZE);
        } finally {
            channel.close(false);
        }
    }

    @Override
    protected <T> void runUpload(String remote, Collection<Option> options, Collection<T> local, AbstractScpClient.ScpOperationExecutor<T> executor) throws IOException {
        local = ValidateUtils.checkNotNullAndNotEmpty(local, "Invalid argument local: %s", local);
        remote = ValidateUtils.checkNotNullAndNotEmpty(remote, "Invalid argument remote: %s", remote);
        if (local.size() > 1) {
            options = addTargetIsDirectory(options);
        }
        
        String cmd = createSendCommand(remote, options);
        ChannelExec channel = clientSession.createExecChannel(cmd);
        channel.open().await();    // TODO use verify + configurable timeout

        try {
            FactoryManager manager = clientSession.getFactoryManager();
            FileSystemFactory factory = manager.getFileSystemFactory();
            FileSystem fs = factory.createFileSystem(clientSession);
            try {
                ScpHelper helper = new ScpHelper(channel.getInvertedOut(), channel.getInvertedIn(), fs, listener);
                executor.execute(helper, local, options);
            } finally {
                try {
                    fs.close();
                } catch(UnsupportedOperationException e) {
                    // Ignore
                }
            }
        } finally {
            channel.close(false);
        }
    }
}
