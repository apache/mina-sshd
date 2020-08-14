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
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;

import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.scp.common.ScpException;
import org.apache.sshd.scp.common.ScpHelper;
import org.apache.sshd.scp.common.helpers.ScpIoUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractScpClient extends AbstractLoggingBean implements ScpClient {
    protected AbstractScpClient() {
        super();
    }

    public boolean isOpen() {
        Session session = getSession();
        return session.isOpen();
    }

    @Override
    public void download(String[] remote, String local, Collection<Option> options) throws IOException {
        local = ValidateUtils.checkNotNullAndNotEmpty(local, "Invalid argument local: %s", local);
        remote = ValidateUtils.checkNotNullAndNotEmpty(remote, "Invalid argument remote: %s", (Object) remote);

        if (remote.length > 1) {
            options = addTargetIsDirectory(options);
        }

        for (String r : remote) {
            download(r, local, options);
        }
    }

    @Override
    public void download(String[] remote, Path local, Collection<Option> options) throws IOException {
        remote = ValidateUtils.checkNotNullAndNotEmpty(remote, "Invalid argument remote: %s", (Object) remote);

        if (remote.length > 1) {
            options = addTargetIsDirectory(options);
        }

        for (String r : remote) {
            download(r, local, options);
        }
    }

    @Override
    public void download(String remote, Path local, Collection<Option> options) throws IOException {
        local = ValidateUtils.checkNotNull(local, "Invalid argument local: %s", local);
        remote = ValidateUtils.checkNotNullAndNotEmpty(remote, "Invalid argument remote: %s", remote);

        LinkOption[] opts = IoUtils.getLinkOptions(true);
        if (Files.isDirectory(local, opts)) {
            options = addTargetIsDirectory(options);
        }

        if (options.contains(Option.TargetIsDirectory)) {
            Boolean status = IoUtils.checkFileExists(local, opts);
            if (status == null) {
                throw new SshException("Target directory " + local.toString() + " is probably inaccesible");
            }

            if (!status) {
                throw new SshException("Target directory " + local.toString() + " does not exist");
            }

            if (!Files.isDirectory(local, opts)) {
                throw new SshException("Target directory " + local.toString() + " is not a directory");
            }
        }

        download(remote, local.getFileSystem(), local, options);
    }

    @Override
    public void download(String remote, String local, Collection<Option> options) throws IOException {
        local = ValidateUtils.checkNotNullAndNotEmpty(local, "Invalid argument local: %s", local);

        ClientSession session = getClientSession();
        FactoryManager manager = session.getFactoryManager();
        FileSystemFactory factory = manager.getFileSystemFactory();
        FileSystem fs = factory.createFileSystem(session);
        try {
            download(remote, fs, fs.getPath(local), options);
        } finally {
            try {
                fs.close();
            } catch (UnsupportedOperationException e) {
                if (log.isDebugEnabled()) {
                    log.debug("download({}) {} => {} - failed ({}) to close file system={}: {}",
                            session, remote, local, e.getClass().getSimpleName(), fs, e.getMessage());
                }
            }
        }
    }

    protected abstract void download(String remote, FileSystem fs, Path local, Collection<Option> options) throws IOException;

    @Override
    public void upload(String[] local, String remote, Collection<Option> options) throws IOException {
        Collection<String> paths
                = Arrays.asList(ValidateUtils.checkNotNullAndNotEmpty(local, "Invalid argument local: %s", (Object) local));
        runUpload(remote, options, paths, (helper, local1, sendOptions) -> helper.send(local1,
                sendOptions.contains(Option.Recursive),
                sendOptions.contains(Option.PreserveAttributes),
                ScpHelper.DEFAULT_SEND_BUFFER_SIZE));
    }

    @Override
    public void upload(Path[] local, String remote, Collection<Option> options) throws IOException {
        Collection<Path> paths
                = Arrays.asList(ValidateUtils.checkNotNullAndNotEmpty(local, "Invalid argument local: %s", (Object) local));
        runUpload(remote, options, paths, (helper, local1, sendOptions) -> helper.sendPaths(local1,
                sendOptions.contains(Option.Recursive),
                sendOptions.contains(Option.PreserveAttributes),
                ScpHelper.DEFAULT_SEND_BUFFER_SIZE));
    }

    protected abstract <T> void runUpload(
            String remote, Collection<Option> options, Collection<T> local, AbstractScpClient.ScpOperationExecutor<T> executor)
            throws IOException;

    /**
     * Invoked by the various <code>upload/download</code> methods after having successfully completed the remote copy
     * command and (optionally) having received an exit status from the remote server. If no exit status received within
     * {@link CoreModuleProperties#CHANNEL_CLOSE_TIMEOUT} the no further action is taken. Otherwise, the exit status is
     * examined to ensure it is either OK or WARNING - if not, an {@link ScpException} is thrown
     *
     * @param  cmd         The attempted remote copy command
     * @param  channel     The {@link ClientChannel} through which the command was sent - <B>Note:</B> then channel may
     *                     be in the process of being closed
     * @throws IOException If failed the command
     * @see                #handleCommandExitStatus(String, Integer)
     */
    protected void handleCommandExitStatus(String cmd, ClientChannel channel) throws IOException {
        ScpIoUtils.handleCommandExitStatus(
                getClientSession(), cmd, channel, (session, command, status) -> handleCommandExitStatus(command, status), log);
    }

    /**
     * Invoked by the various <code>upload/download</code> methods after having successfully completed the remote copy
     * command and (optionally) having received an exit status from the remote server
     *
     * @param  cmd         The attempted remote copy command
     * @param  exitStatus  The exit status - if {@code null} then no status was reported
     * @throws IOException If received non-OK exit status
     */
    protected void handleCommandExitStatus(String cmd, Integer exitStatus) throws IOException {
        ScpIoUtils.handleCommandExitStatus(getClientSession(), cmd, exitStatus, log);
    }

    protected Collection<Option> addTargetIsDirectory(Collection<Option> options) {
        if (GenericUtils.isEmpty(options) || (!options.contains(Option.TargetIsDirectory))) {
            // create a copy in case the original collection is un-modifiable
            options = GenericUtils.isEmpty(options) ? EnumSet.noneOf(Option.class) : GenericUtils.of(options);
            options.add(Option.TargetIsDirectory);
        }

        return options;
    }

    protected ChannelExec openCommandChannel(ClientSession session, String cmd) throws IOException {
        return ScpIoUtils.openCommandChannel(session, cmd, log);
    }

    @FunctionalInterface
    public interface ScpOperationExecutor<T> {
        void execute(ScpHelper helper, Collection<T> local, Collection<Option> options) throws IOException;
    }
}
