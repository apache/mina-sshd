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
package org.apache.sshd.sftp.spring.integration;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClient.Attributes;
import org.apache.sshd.sftp.client.SftpClient.DirEntry;
import org.apache.sshd.sftp.client.SftpClient.OpenMode;
import org.apache.sshd.sftp.common.SftpException;
import org.springframework.integration.file.remote.session.Session;
import org.springframework.util.FileCopyUtils;

/**
 * Implements the <I>Spring</I> session for the SFTP client
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SpringSftpSession extends AbstractLoggingBean implements Session<DirEntry> {
    private final SftpClient sftpClient;
    private final Callable<Exception> sessionCloser;

    public SpringSftpSession(SftpClient clientInstance) {
        this(clientInstance, () -> null);
    }

    public SpringSftpSession(SftpClient clientInstance, Callable<Exception> sessionCloser) {
        this.sftpClient = Objects.requireNonNull(clientInstance, "No SFTP client instance");
        this.sessionCloser = sessionCloser;
    }

    @Override
    public String getHostPort() {
        SftpClient client = getClientInstance();
        @SuppressWarnings("resource")
        org.apache.sshd.common.session.Session session = (client == null) ? null : client.getSession();
        @SuppressWarnings("resource")
        IoSession ioSession = (session == null) ? null : session.getIoSession();
        SocketAddress peerAddress = (ioSession == null) ? null : ioSession.getRemoteAddress();
        if (peerAddress instanceof InetSocketAddress) {
            InetSocketAddress inetAddress = (InetSocketAddress) peerAddress;
            return inetAddress.getHostString() + ":" + inetAddress.getPort();
        } else if (peerAddress instanceof SshdSocketAddress) {
            SshdSocketAddress sshdAddress = (SshdSocketAddress) peerAddress;
            return sshdAddress.getHostName() + ":" + sshdAddress.getPort();
        } else {
            return Objects.toString(peerAddress, null);
        }
    }

    @Override
    public boolean isOpen() {
        SftpClient client = getClientInstance();
        return client.isOpen();
    }

    @Override
    public SftpClient getClientInstance() {
        return sftpClient;
    }

    public Callable<Exception> getSessionCloser() {
        return sessionCloser;
    }

    @Override
    public void close() {
        Exception err = null;
        try {
            SftpClient client = getClientInstance();
            closeClientInstance(client);
        } catch (Exception e) {
            err = GenericUtils.accumulateException(err, e);
        }

        try {
            closeSessionInstance(getSessionCloser());
        } catch (Exception e) {
            err = GenericUtils.accumulateException(err, e);
        }

        if (err != null) {
            throw GenericUtils.toRuntimeException(err);
        }
    }

    protected void closeClientInstance(SftpClient client) throws Exception {
        if (client.isOpen()) {
            client.close();
        }
    }

    protected void closeSessionInstance(Callable<Exception> closer) throws Exception {
        if (closer == null) {
            return;
        }

        Exception err;
        try {
            err = closer.call();
        } catch (Exception e) {
            err = e;
        }

        if (err != null) {
            throw err;
        }
    }

    @Override
    public boolean remove(String path) throws IOException {
        SftpClient client = getClientInstance();
        if (log.isDebugEnabled()) {
            log.debug("remove({})[{}]", client, path);
        }
        client.remove(path);
        return true;
    }

    @Override
    public boolean mkdir(String directory) throws IOException {
        SftpClient client = getClientInstance();
        if (log.isDebugEnabled()) {
            log.debug("mkdir({})[{}]", client, directory);
        }
        client.mkdir(directory);
        return true;
    }

    @Override
    public boolean rmdir(String directory) throws IOException {
        SftpClient client = getClientInstance();
        if (log.isDebugEnabled()) {
            log.debug("rmdir({})[{}]", client, directory);
        }
        client.rmdir(directory);
        return true;
    }

    @Override
    public void rename(String pathFrom, String pathTo) throws IOException {
        SftpClient client = getClientInstance();
        boolean debugEnabled = log.isDebugEnabled();
        if (exists(pathTo)) {
            if (debugEnabled) {
                log.debug("rename({})[{} => {}] target exists - attempting to remove", client, pathFrom, pathTo);
            }
            remove(pathTo);
        }

        if (debugEnabled) {
            log.debug("rename({})[{} => {}] renaming", client, pathFrom, pathTo);
        }
        client.rename(pathFrom, pathTo);
    }

    @Override
    public boolean exists(String path) throws IOException {
        SftpClient client = getClientInstance();
        try {
            Attributes attrs = client.lstat(path);
            return attrs != null;
        } catch (SftpException e) {
            if (log.isDebugEnabled()) {
                log.debug("exists({})[{}]: {} - {}", client, path, e.getStatus(), e.getMessage());
            }
            return false;
        }
    }

    @Override
    public String[] listNames(String path) throws IOException {
        DirEntry[] entries = list(path);
        if (GenericUtils.isEmpty(entries)) {
            return GenericUtils.EMPTY_STRING_ARRAY;
        }

        Collection<String> names = new LinkedList<>();
        for (int index = 0; index < entries.length; index++) {
            DirEntry de = entries[index];
            Attributes attrs = de.getAttributes();
            if (!attrs.isRegularFile()) {
                continue;
            }
            if (attrs.isSymbolicLink()) {
                continue;
            }

            String n = de.getFilename();
            if (".".equals(n) || "..".equals(n)) {
                continue;
            }

            names.add(n);
        }

        if (GenericUtils.isEmpty(names)) {
            return GenericUtils.EMPTY_STRING_ARRAY;
        }

        return names.toArray(new String[names.size()]);
    }

    @Override
    public DirEntry[] list(String path) throws IOException {
        SftpClient client = getClientInstance();
        Iterable<DirEntry> entries = client.readDir(path);
        Collection<DirEntry> result = GenericUtils.stream(entries).collect(Collectors.toCollection(LinkedList::new));
        if (GenericUtils.isEmpty(result)) {
            return SftpClient.EMPTY_DIR_ENTRIES;
        }

        return result.toArray(new DirEntry[result.size()]);
    }

    @Override
    public void read(String source, OutputStream outputStream) throws IOException {
        SftpClient client = getClientInstance();
        try (InputStream inputStream = client.read(source)) {
            FileCopyUtils.copy(inputStream, outputStream);
        }
    }

    @Override
    public void write(InputStream inputStream, String destination) throws IOException {
        SftpClient client = getClientInstance();
        try (OutputStream outputStream = client.write(destination)) {
            FileCopyUtils.copy(inputStream, outputStream);
        }
    }

    @Override
    public void append(InputStream inputStream, String destination) throws IOException {
        SftpClient client = getClientInstance();
        try (OutputStream outputStream = client.write(destination, OpenMode.Append)) {
            FileCopyUtils.copy(inputStream, outputStream);
        }
    }

    @Override
    public InputStream readRaw(String source) throws IOException {
        SftpClient client = getClientInstance();
        return client.read(source);
    }

    @Override
    public boolean finalizeRaw() throws IOException {
        return true;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getClientInstance() + "]";
    }
}
