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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.ClientSession;
import org.apache.sshd.client.ScpClient;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.FileSystemView;
import org.apache.sshd.common.file.SshFile;
import org.apache.sshd.common.scp.ScpHelper;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultScpClient implements ScpClient {

    private final ClientSession clientSession;

    public DefaultScpClient(ClientSession clientSession) {
        this.clientSession = clientSession;
    }

    public void download(String remote, String local, Option... options) throws IOException {
        local = checkNotNullAndNotEmpty(local, "Invalid argument local: {}");
        remote = checkNotNullAndNotEmpty(remote, "Invalid argument remote: {}");
        download(remote, local, Arrays.asList(options));
    }

    public void download(String[] remote, String local, Option... options) throws IOException {
        local = checkNotNullAndNotEmpty(local, "Invalid argument local: {}");
        remote = checkNotNullAndNotEmpty(remote, "Invalid argument remote: {}");
        List<Option> opts = options(options);
        if (remote.length > 1) {
            opts.add(Option.TargetIsDirectory);
        }
        for (String r : remote) {
            download(r, local, opts);
        }
    }

    protected void download(String remote, String local, Collection<Option> options) throws IOException {
        local = checkNotNullAndNotEmpty(local, "Invalid argument local: {}");
        remote = checkNotNullAndNotEmpty(remote, "Invalid argument remote: {}");

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

        FileSystemFactory factory = clientSession.getFactoryManager().getFileSystemFactory();
        FileSystemView fs = factory.createFileSystemView(clientSession);
        SshFile target = fs.getFile(local);
        if (options.contains(Option.TargetIsDirectory)) {
            if (!target.doesExist()) {
                throw new SshException("Target directory " + target.toString() + " does not exists");
            }
            if (!target.isDirectory()) {
                throw new SshException("Target directory " + target.toString() + " is not a directory");
            }
        }

        ChannelExec channel = clientSession.createExecChannel(sb.toString());
        try {
            channel.open().await();
        } catch (InterruptedException e) {
            throw (IOException) new InterruptedIOException().initCause(e);
        }

        ScpHelper helper = new ScpHelper(channel.getInvertedOut(), channel.getInvertedIn(), fs);

        helper.receive(target,
                       options.contains(Option.Recursive),
                       options.contains(Option.TargetIsDirectory),
                       options.contains(Option.PreserveAttributes),
                       ScpHelper.DEFAULT_RECEIVE_BUFFER_SIZE);

        channel.close(false);
    }

    public void upload(String local, String remote, Option... options) throws IOException {
        local = checkNotNullAndNotEmpty(local, "Invalid argument local: {}");
        remote = checkNotNullAndNotEmpty(remote, "Invalid argument remote: {}");
        upload(new String[] { local }, remote, options(options));
    }

    public void upload(String[] local, String remote, Option... options) throws IOException {
        local = checkNotNullAndNotEmpty(local, "Invalid argument local: {}");
        remote = checkNotNullAndNotEmpty(remote, "Invalid argument remote: {}");
        List<Option> opts = options(options);
        if (local.length > 1) {
            opts.add(Option.TargetIsDirectory);
        }
        upload(local, remote, opts);
    }

    protected void upload(String[] local, String remote, Collection<Option> options) throws IOException {
        local = checkNotNullAndNotEmpty(local, "Invalid argument local: {}");
        remote = checkNotNullAndNotEmpty(remote, "Invalid argument remote: {}");
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

        FileSystemFactory factory = clientSession.getFactoryManager().getFileSystemFactory();
        FileSystemView fs = factory.createFileSystemView(clientSession);
        ScpHelper helper = new ScpHelper(channel.getInvertedOut(), channel.getInvertedIn(), fs);

        helper.send(Arrays.asList(local),
                    options.contains(Option.Recursive),
                    options.contains(Option.PreserveAttributes),
                    ScpHelper.DEFAULT_SEND_BUFFER_SIZE);

        channel.close(false);
    }

    private List<Option> options(Option... options) {
        List<Option> opts = new ArrayList<Option>();
        if (options != null) {
            opts.addAll(Arrays.asList(options));
        }
        return opts;
    }

    private <T> T checkNotNull(T t, String message) {
        if (t == null) {
            throw new IllegalStateException(String.format(message, t));
        }
        return t;
    }

    private String checkNotNullAndNotEmpty(String t, String message) {
        t = checkNotNull(t, message).trim();
        if (t.isEmpty()) {
            throw new IllegalArgumentException(String.format(message, t));
        }
        return t;
    }

    private <T> T[] checkNotNullAndNotEmpty(T[] t, String message) {
        t = checkNotNull(t, message);
        if (t.length == 0) {
            throw new IllegalArgumentException(String.format(message, t));
        }
        return t;
    }
}
