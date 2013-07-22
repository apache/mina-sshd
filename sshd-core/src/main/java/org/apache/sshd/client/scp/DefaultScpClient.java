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
import java.util.Arrays;

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

    public void download(String remote, String local) throws IOException {
        download(new String[] { remote }, local, false, false);
    }

    public void download(String remote, String local, boolean recursive) throws IOException {
        download(new String[] { remote }, local, recursive, false);
    }

    public void download(String[] remote, String local) throws IOException {
        download(remote, local, false, true);
    }

    public void download(String[] remote, String local, boolean recursive) throws IOException {
        download(remote, local, recursive, true);
    }

    private void download(String[] remote, String local, boolean recursive, boolean shouldBeDir) throws IOException {
        local = checkNotNullAndNotEmpty(local, "Invalid argument local: {}");
        remote = checkNotNullAndNotEmpty(remote, "Invalid argument remote: {}");
        StringBuilder sb = new StringBuilder("scp");
        if (recursive) {
            sb.append(" -r");
        }
        sb.append(" -f");
        for (String r : remote) {
            r = checkNotNullAndNotEmpty(r, "Invalid argument remote: {}");
            sb.append(" ").append(r);
        }

        FileSystemFactory factory = clientSession.getFactoryManager().getFileSystemFactory();
        FileSystemView fs = factory.createFileSystemView(clientSession);
        SshFile target = fs.getFile(local);
        if (shouldBeDir) {
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

        helper.receive(target, recursive, shouldBeDir);

        channel.close(false);
    }

    public void upload(String remote, String local) throws IOException {
        upload(new String[] { remote }, local, false, false);
    }

    public void upload(String remote, String local, boolean recursive) throws IOException {
        upload(new String[] { remote }, local, recursive, false);
    }

    public void upload(String[] local, String remote) throws IOException {
        upload(local, remote, false, true);
    }

    public void upload(String[] local, String remote, boolean recursive) throws IOException {
        upload(local, remote, false, true);
    }

    private void upload(String[] local, String remote, boolean recursive, boolean shouldBeDir) throws IOException {
        local = checkNotNullAndNotEmpty(local, "Invalid argument local: {}");
        remote = checkNotNullAndNotEmpty(remote, "Invalid argument remote: {}");
        StringBuilder sb = new StringBuilder("scp");
        if (recursive) {
            sb.append(" -r");
        }
        if (shouldBeDir) {
            sb.append(" -d");
        }
        sb.append(" -t");
        for (String r : local) {
            r = checkNotNullAndNotEmpty(r, "Invalid argument remote: {}");
            sb.append(" ").append(r);
        }
        ChannelExec channel = clientSession.createExecChannel(sb.toString());
        try {
            channel.open().await();
        } catch (InterruptedException e) {
            throw (IOException) new InterruptedIOException().initCause(e);
        }

        FileSystemFactory factory = clientSession.getFactoryManager().getFileSystemFactory();
        FileSystemView fs = factory.createFileSystemView(clientSession);
        ScpHelper helper = new ScpHelper(channel.getInvertedOut(), channel.getInvertedIn(), fs);
        SshFile target = fs.getFile(remote);

        helper.send(Arrays.asList(local), recursive);

        channel.close(false);
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
