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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.scp.ScpHelper;
import org.apache.sshd.common.scp.ScpTimestamp;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractScpClient extends AbstractLoggingBean implements ScpClient {
    protected AbstractScpClient() {
        super();
    }

    @Override
    public void download(String remote, String local, Option... options) throws IOException {
        download(remote, local, GenericUtils.isEmpty(options) ? Collections.<Option>emptySet() : GenericUtils.of(options));
    }

    @Override
    public void download(String[] remote, String local, Option... options) throws IOException {
        download(remote, local, GenericUtils.isEmpty(options) ? Collections.<Option>emptySet() : GenericUtils.of(options));
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
    public void download(String[] remote, Path local, Option... options) throws IOException {
        download(remote, local, GenericUtils.isEmpty(options) ? Collections.<Option>emptySet() : GenericUtils.of(options));
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
    public void download(String remote, Path local, Option... options) throws IOException {
        download(remote, local, GenericUtils.of(options));
    }

    @Override
    public void download(String remote, Path local, Collection<Option> options) throws IOException {
        local = ValidateUtils.checkNotNull(local, "Invalid argument local: %s", local);
        remote = ValidateUtils.checkNotNullAndNotEmpty(remote, "Invalid argument remote: %s", remote);

        LinkOption[] opts = IoUtils.getLinkOptions(false);
        if (Files.isDirectory(local, opts)) {
            options = addTargetIsDirectory(options);
        }

        if (options.contains(Option.TargetIsDirectory)) {
            Boolean status = IoUtils.checkFileExists(local, opts);
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
                // Ignore
            }
        }
    }

    protected abstract void download(String remote, FileSystem fs, Path local, Collection<Option> options) throws IOException;

    @Override
    public byte[] downloadBytes(String remote) throws IOException {
        try (ByteArrayOutputStream local = new ByteArrayOutputStream()) {
            download(remote, local);
            return local.toByteArray();
        }
    }

    @Override
    public void upload(String local, String remote, Option... options) throws IOException {
        upload(local, remote, GenericUtils.of(options));
    }

    @Override
    public void upload(String local, String remote, Collection<Option> options) throws IOException {
        upload(new String[]{ValidateUtils.checkNotNullAndNotEmpty(local, "Invalid argument local: %s", local)}, remote, options);
    }

    @Override
    public void upload(String[] local, String remote, Option... options) throws IOException {
        upload(local, remote, GenericUtils.isEmpty(options) ? Collections.<Option>emptySet() : GenericUtils.of(options));
    }

    @Override
    public void upload(Path local, String remote, Option... options) throws IOException {
        upload(local, remote, GenericUtils.isEmpty(options) ? Collections.<Option>emptySet() : GenericUtils.of(options));
    }

    @Override
    public void upload(Path local, String remote, Collection<Option> options) throws IOException {
        upload(new Path[]{ValidateUtils.checkNotNull(local, "Invalid local argument: %s", local)},
                remote, GenericUtils.isEmpty(options) ? Collections.<Option>emptySet() : GenericUtils.of(options));
    }

    @Override
    public void upload(Path[] local, String remote, Option... options) throws IOException {
        upload(local, remote, GenericUtils.isEmpty(options) ? Collections.<Option>emptySet() : GenericUtils.of(options));
    }

    @Override
    public void upload(byte[] data, String remote, Collection<PosixFilePermission> perms, ScpTimestamp time) throws IOException {
        upload(data, 0, data.length, remote, perms, time);
    }

    @Override
    public void upload(byte[] data, int offset, int len, String remote, Collection<PosixFilePermission> perms, ScpTimestamp time) throws IOException {
        try (InputStream local = new ByteArrayInputStream(data, offset, len)) {
            upload(local, remote, len, perms, time);
        }
    }

    @Override
    public void upload(String[] local, String remote, Collection<Option> options) throws IOException {
        final Collection<String> paths = Arrays.asList(ValidateUtils.checkNotNullAndNotEmpty(local, "Invalid argument local: %s", (Object) local));
        runUpload(remote, options, paths, new ScpOperationExecutor<String>() {
            @Override
            public void execute(ScpHelper helper, Collection<String> local, Collection<Option> sendOptions) throws IOException {
                helper.send(local, sendOptions.contains(Option.Recursive), sendOptions.contains(Option.PreserveAttributes), ScpHelper.DEFAULT_SEND_BUFFER_SIZE);
            }
        });
    }

    @Override
    public void upload(Path[] local, String remote, Collection<Option> options) throws IOException {
        final Collection<Path> paths = Arrays.asList(ValidateUtils.checkNotNullAndNotEmpty(local, "Invalid argument local: %s", (Object) local));
        runUpload(remote, options, paths, new ScpOperationExecutor<Path>() {
            @Override
            public void execute(ScpHelper helper, Collection<Path> local, Collection<Option> sendOptions) throws IOException {
                helper.sendPaths(local, sendOptions.contains(Option.Recursive), sendOptions.contains(Option.PreserveAttributes), ScpHelper.DEFAULT_SEND_BUFFER_SIZE);
            }
        });
    }

    protected abstract <T> void runUpload(String remote, Collection<Option> options, Collection<T> local, AbstractScpClient.ScpOperationExecutor<T> executor) throws IOException;

    protected Collection<Option> addTargetIsDirectory(Collection<Option> options) {
        if (GenericUtils.isEmpty(options) || (!options.contains(Option.TargetIsDirectory))) {
            // create a copy in case the original collection is un-modifiable
            options = GenericUtils.isEmpty(options) ? EnumSet.noneOf(Option.class) : GenericUtils.of(options);
            options.add(Option.TargetIsDirectory);
        }

        return options;
    }

    protected ChannelExec openCommandChannel(ClientSession session, String cmd) throws IOException {
        long waitTimeout = PropertyResolverUtils.getLongProperty(session, SCP_EXEC_CHANNEL_OPEN_TIMEOUT, DEFAULT_EXEC_CHANNEL_OPEN_TIMEOUT);
        ChannelExec channel = session.createExecChannel(cmd);

        long startTime = System.nanoTime();
        try {
            channel.open().verify(waitTimeout);
            long endTime = System.nanoTime();
            long nanosWait = endTime - startTime;
            if (log.isTraceEnabled()) {
                log.trace("openCommandChannel(" + session + ")[" + cmd + "]"
                        + " completed after " + nanosWait
                        + " nanos out of " + TimeUnit.MILLISECONDS.toNanos(waitTimeout));
            }

            return channel;
        } catch (IOException | RuntimeException e) {
            long endTime = System.nanoTime();
            long nanosWait = endTime - startTime;
            if (log.isTraceEnabled()) {
                log.trace("openCommandChannel(" + session + ")[" + cmd + "]"
                        + " failed (" + e.getClass().getSimpleName() + ")"
                        + " to complete after " + nanosWait
                        + " nanos out of " + TimeUnit.MILLISECONDS.toNanos(waitTimeout)
                        + ": " + e.getMessage());
            }

            channel.close(false);
            throw e;
        }
    }

    public static String createSendCommand(String remote, Collection<Option> options) {
        StringBuilder sb = new StringBuilder(remote.length() + Long.SIZE).append(ScpHelper.SCP_COMMAND_PREFIX);
        if (options.contains(Option.Recursive)) {
            sb.append(" -r");
        }
        if (options.contains(Option.TargetIsDirectory)) {
            sb.append(" -d");
        }
        if (options.contains(Option.PreserveAttributes)) {
            sb.append(" -p");
        }

        sb.append(" -t").append(" --").append(" ").append(remote);
        return sb.toString();
    }

    public static String createReceiveCommand(String remote, Collection<Option> options) {
        ValidateUtils.checkNotNullAndNotEmpty(remote, "No remote location specified");
        StringBuilder sb = new StringBuilder(remote.length() + Long.SIZE).append(ScpHelper.SCP_COMMAND_PREFIX);
        if (options.contains(Option.Recursive)) {
            sb.append(" -r");
        }
        if (options.contains(Option.PreserveAttributes)) {
            sb.append(" -p");
        }

        sb.append(" -f").append(" --").append(' ').append(remote);
        return sb.toString();
    }

    public interface ScpOperationExecutor<T> {
        void execute(ScpHelper helper, Collection<T> local, Collection<Option> options) throws IOException;
    }
}
