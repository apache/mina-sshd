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
import java.io.InterruptedIOException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;

import org.apache.sshd.ClientSession;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.scp.ScpHelper;
import org.apache.sshd.common.scp.ScpTransferEventListener;
import org.apache.sshd.common.util.IoUtils;
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
        local = ValidateUtils.checkNotNullAndNotEmpty(local, "Invalid argument local: %s");

        FileSystemFactory factory = clientSession.getFactoryManager().getFileSystemFactory();
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
    public void download(String remote, Path local, Collection<Option> options) throws IOException {
        local = ValidateUtils.checkNotNull(local, "Invalid argument local: %s");
        download(remote, local.getFileSystem(), local, options);
    }

    protected void download(String remote, FileSystem fs, Path local, Collection<Option> options) throws IOException {
        local = ValidateUtils.checkNotNull(local, "Invalid argument local: %s");
        remote = ValidateUtils.checkNotNullAndNotEmpty(remote, "Invalid argument remote: %s");

        LinkOption[]    opts = IoUtils.getLinkOptions(false);
        if (Files.isDirectory(local, opts)) {
            options = addTargetIsDirectory(options);
        }

        if (options.contains(Option.TargetIsDirectory)) {
            Boolean         status = IoUtils.checkFileExists(local, opts);
            if (status == null) {
                throw new SshException("Target directory " + local.toString() + " is probaly inaccesible");
            }

            if (!status.booleanValue()) {
                throw new SshException("Target directory " + local.toString() + " does not exist");
            }
            if (!Files.isDirectory(local, opts)) {
                throw new SshException("Target directory " + local.toString() + " is not a directory");
            }
        }

        StringBuilder sb = new StringBuilder("scp");
        if (options.contains(Option.Recursive)) {
            sb.append(" -r");
        }
        if (options.contains(Option.PreserveAttributes)) {
            sb.append(" -p");
        }
        sb.append(" -f");
        sb.append(" --");
        sb.append(" ");
        sb.append(remote);

        ChannelExec channel = clientSession.createExecChannel(sb.toString());
        try {
            try {
                channel.open().await();
            } catch (InterruptedException e) {
                throw (IOException) new InterruptedIOException().initCause(e);
            }

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
    public void upload(String[] local, String remote, Collection<Option> options) throws IOException {
        final Collection<String>    paths=Arrays.asList(ValidateUtils.checkNotNullAndNotEmpty(local, "Invalid argument local: %s"));
        runUpload(remote, options, paths, new ScpOperationExecutor<String>() {
            public void execute(ScpHelper helper, Collection<String> local, Collection<Option> options) throws IOException {
                helper.send(local,
                        options.contains(Option.Recursive),
                        options.contains(Option.PreserveAttributes),
                        ScpHelper.DEFAULT_SEND_BUFFER_SIZE);
            }
        });
    }

    @Override
    public void upload(Path[] local, String remote, Collection<Option> options) throws IOException {
        final Collection<Path>    paths=Arrays.asList(ValidateUtils.checkNotNullAndNotEmpty(local, "Invalid argument local: %s"));
        runUpload(remote, options, paths, new ScpOperationExecutor<Path>() {
            public void execute(ScpHelper helper, Collection<Path> local, Collection<Option> options) throws IOException {
                helper.sendPaths(local,
                        options.contains(Option.Recursive),
                        options.contains(Option.PreserveAttributes),
                        ScpHelper.DEFAULT_SEND_BUFFER_SIZE);
            }
        });
    }

    protected <T> void runUpload(String remote, Collection<Option> options, Collection<T> local, ScpOperationExecutor<T> executor) throws IOException {
        local = ValidateUtils.checkNotNullAndNotEmpty(local, "Invalid argument local: %s");
        remote = ValidateUtils.checkNotNullAndNotEmpty(remote, "Invalid argument remote: %s");
        if (local.size() > 1) {
            options = addTargetIsDirectory(options);
        }
        
        StringBuilder sb = new StringBuilder("scp");
        if (options.contains(Option.Recursive)) {
            sb.append(" -r");
        }
        if (options.contains(Option.TargetIsDirectory)) {
            sb.append(" -d");
        }
        if (options.contains(Option.PreserveAttributes)) {
            sb.append(" -p");
        }
        sb.append(" -t");
        sb.append(" --");
        sb.append(" ");
        sb.append(remote);

        ChannelExec channel = clientSession.createExecChannel(sb.toString());
        try {
            channel.open().await();
        } catch (InterruptedException e) {
            throw (IOException) new InterruptedIOException().initCause(e);
        }

        try {
            FileSystemFactory factory = clientSession.getFactoryManager().getFileSystemFactory();
            FileSystem fs = factory.createFileSystem(clientSession);
            try {
                ScpHelper helper = new ScpHelper(channel.getInvertedOut(), channel.getInvertedIn(), fs, listener);
                executor.execute(helper, local, options);
            } finally {
                try {
                    fs.close();
                } catch (UnsupportedOperationException e) {
                    // Ignore
                }
            }
        } finally {
            channel.close(false);
        }
    }
    
    public static interface ScpOperationExecutor<T> {
        void execute(ScpHelper helper, Collection<T> local, Collection<Option> options) throws IOException;
    }
}
