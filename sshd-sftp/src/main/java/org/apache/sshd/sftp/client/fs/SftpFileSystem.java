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
package org.apache.sshd.sftp.client.fs;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.nio.charset.Charset;
import java.nio.file.FileStore;
import java.nio.file.FileSystemException;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.NavigableMap;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.Queue;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionHolder;
import org.apache.sshd.common.file.util.BaseFileSystem;
import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.sftp.SftpModuleProperties;
import org.apache.sshd.sftp.client.RawSftpClient;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.apache.sshd.sftp.client.SftpVersionSelector;
import org.apache.sshd.sftp.client.impl.AbstractSftpClient;
import org.apache.sshd.sftp.common.SftpConstants;

public class SftpFileSystem
        extends BaseFileSystem<SftpPath>
        implements SessionHolder<ClientSession>, ClientSessionHolder {

    public static final NavigableSet<String> UNIVERSAL_SUPPORTED_VIEWS = Collections.unmodifiableNavigableSet(
            GenericUtils.asSortedSet(String.CASE_INSENSITIVE_ORDER, "basic", "posix", "owner"));

    private final String id;
    private final ClientSession clientSession;
    private final SftpClientFactory factory;
    private final SftpVersionSelector selector;
    private final Queue<SftpClient> pool;
    private final ThreadLocal<Wrapper> wrappers = new ThreadLocal<>();
    private final int version;
    private final Set<String> supportedViews;
    private SftpPath defaultDir;
    private int readBufferSize;
    private int writeBufferSize;
    private final List<FileStore> stores;

    public SftpFileSystem(SftpFileSystemProvider provider, String id, ClientSession session,
                          SftpClientFactory factory, SftpVersionSelector selector) throws IOException {
        super(provider);
        this.id = id;
        this.clientSession = Objects.requireNonNull(session, "No client session");
        this.factory = factory != null ? factory : SftpClientFactory.instance();
        this.selector = selector;
        this.stores = Collections.unmodifiableList(Collections.<FileStore> singletonList(new SftpFileStore(id, this)));
        this.pool = new LinkedBlockingQueue<>(SftpModuleProperties.POOL_SIZE.getRequired(session));
        try (SftpClient client = getClient()) {
            version = client.getVersion();
            defaultDir = getPath(client.canonicalPath("."));
        }

        if (version >= SftpConstants.SFTP_V4) {
            Set<String> views = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
            views.addAll(UNIVERSAL_SUPPORTED_VIEWS);
            views.add("acl");
            supportedViews = Collections.unmodifiableSet(views);
        } else {
            supportedViews = UNIVERSAL_SUPPORTED_VIEWS;
        }
    }

    public final SftpVersionSelector getSftpVersionSelector() {
        return selector;
    }

    public final String getId() {
        return id;
    }

    public final int getVersion() {
        return version;
    }

    @Override
    public SftpFileSystemProvider provider() {
        return (SftpFileSystemProvider) super.provider();
    }

    @Override // NOTE: co-variant return
    public List<FileStore> getFileStores() {
        return this.stores;
    }

    public int getReadBufferSize() {
        return readBufferSize;
    }

    public void setReadBufferSize(int size) {
        if (size < SftpClient.MIN_READ_BUFFER_SIZE) {
            throw new IllegalArgumentException(
                    "Insufficient read buffer size: " + size + ", min.=" + SftpClient.MIN_READ_BUFFER_SIZE);
        }

        readBufferSize = size;
    }

    public int getWriteBufferSize() {
        return writeBufferSize;
    }

    public void setWriteBufferSize(int size) {
        if (size < SftpClient.MIN_WRITE_BUFFER_SIZE) {
            throw new IllegalArgumentException(
                    "Insufficient write buffer size: " + size + ", min.=" + SftpClient.MIN_WRITE_BUFFER_SIZE);
        }

        writeBufferSize = size;
    }

    @Override
    protected SftpPath create(String root, List<String> names) {
        return new SftpPath(this, root, names);
    }

    @Override
    public ClientSession getClientSession() {
        return clientSession;
    }

    @Override
    public ClientSession getSession() {
        return getClientSession();
    }

    @SuppressWarnings("synthetic-access")
    public SftpClient getClient() throws IOException {
        Wrapper wrapper = wrappers.get();
        if (wrapper == null) {
            while (wrapper == null) {
                SftpClient client = pool.poll();
                if (client == null) {
                    ClientSession session = getClientSession();
                    client = factory.createSftpClient(session, getSftpVersionSelector());
                }
                if (!client.isClosing()) {
                    wrapper = new Wrapper(client, getReadBufferSize(), getWriteBufferSize());
                }
            }
            wrappers.set(wrapper);
        } else {
            wrapper.increment();
        }
        return wrapper;
    }

    @Override
    public void close() throws IOException {
        if (isOpen()) {
            SftpFileSystemProvider provider = provider();
            String fsId = getId();
            SftpFileSystem fs = provider.removeFileSystem(fsId);
            ClientSession session = getClientSession();
            session.close(true);

            if ((fs != null) && (fs != this)) {
                throw new FileSystemException(fsId, fsId, "Mismatched FS instance for id=" + fsId);
            }
        }
    }

    @Override
    public boolean isOpen() {
        ClientSession session = getClientSession();
        return session.isOpen();
    }

    @Override
    public Set<String> supportedFileAttributeViews() {
        return supportedViews;
    }

    @Override
    public UserPrincipalLookupService getUserPrincipalLookupService() {
        return DefaultUserPrincipalLookupService.INSTANCE;
    }

    @Override
    public SftpPath getDefaultDir() {
        return defaultDir;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getClientSession() + "]";
    }

    private final class Wrapper extends AbstractSftpClient {
        private final SftpClient delegate;
        private final AtomicInteger count = new AtomicInteger(1);
        private final int readSize;
        private final int writeSize;

        private Wrapper(SftpClient delegate, int readSize, int writeSize) {
            this.delegate = delegate;
            this.readSize = readSize;
            this.writeSize = writeSize;
        }

        @Override
        public int getVersion() {
            return delegate.getVersion();
        }

        @Override
        public ClientSession getClientSession() {
            return delegate.getClientSession();
        }

        @Override
        public ClientChannel getClientChannel() {
            return delegate.getClientChannel();
        }

        @Override
        public NavigableMap<String, byte[]> getServerExtensions() {
            return delegate.getServerExtensions();
        }

        @Override
        public Charset getNameDecodingCharset() {
            return delegate.getNameDecodingCharset();
        }

        @Override
        public void setNameDecodingCharset(Charset cs) {
            delegate.setNameDecodingCharset(cs);
        }

        @Override
        public boolean isClosing() {
            return false;
        }

        @Override
        public boolean isOpen() {
            return count.get() > 0;
        }

        @SuppressWarnings("synthetic-access")
        @Override
        public void close() throws IOException {
            if (count.decrementAndGet() <= 0) {
                if (!pool.offer(delegate)) {
                    delegate.close();
                }
                wrappers.set(null);
            }
        }

        public void increment() {
            count.incrementAndGet();
        }

        @Override
        public CloseableHandle open(String path, Collection<OpenMode> options) throws IOException {
            if (!isOpen()) {
                throw new IOException("open(" + path + ")[" + options + "] client is closed");
            }
            return delegate.open(path, options);
        }

        @Override
        public void close(Handle handle) throws IOException {
            if (!isOpen()) {
                throw new IOException("close(" + handle + ") client is closed");
            }
            delegate.close(handle);
        }

        @Override
        public void remove(String path) throws IOException {
            if (!isOpen()) {
                throw new IOException("remove(" + path + ") client is closed");
            }
            delegate.remove(path);
        }

        @Override
        public void rename(String oldPath, String newPath, Collection<CopyMode> options) throws IOException {
            if (!isOpen()) {
                throw new IOException("rename(" + oldPath + " => " + newPath + ")[" + options + "] client is closed");
            }
            delegate.rename(oldPath, newPath, options);
        }

        @Override
        public int read(Handle handle, long fileOffset, byte[] dst, int dstOffset, int len) throws IOException {
            if (!isOpen()) {
                throw new IOException(
                        "read(" + handle + "/" + fileOffset + ")[" + dstOffset + "/" + len + "] client is closed");
            }
            return delegate.read(handle, fileOffset, dst, dstOffset, len);
        }

        @Override
        public void write(Handle handle, long fileOffset, byte[] src, int srcOffset, int len) throws IOException {
            if (!isOpen()) {
                throw new IOException(
                        "write(" + handle + "/" + fileOffset + ")[" + srcOffset + "/" + len + "] client is closed");
            }
            delegate.write(handle, fileOffset, src, srcOffset, len);
        }

        @Override
        public void mkdir(String path) throws IOException {
            if (!isOpen()) {
                throw new IOException("mkdir(" + path + ") client is closed");
            }
            delegate.mkdir(path);
        }

        @Override
        public void rmdir(String path) throws IOException {
            if (!isOpen()) {
                throw new IOException("rmdir(" + path + ") client is closed");
            }
            delegate.rmdir(path);
        }

        @Override
        public CloseableHandle openDir(String path) throws IOException {
            if (!isOpen()) {
                throw new IOException("openDir(" + path + ") client is closed");
            }
            return delegate.openDir(path);
        }

        @Override
        public List<DirEntry> readDir(Handle handle) throws IOException {
            if (!isOpen()) {
                throw new IOException("readDir(" + handle + ") client is closed");
            }
            return delegate.readDir(handle);
        }

        @Override
        public Iterable<DirEntry> listDir(Handle handle) throws IOException {
            if (!isOpen()) {
                throw new IOException("readDir(" + handle + ") client is closed");
            }
            return delegate.listDir(handle);
        }

        @Override
        public String canonicalPath(String path) throws IOException {
            if (!isOpen()) {
                throw new IOException("canonicalPath(" + path + ") client is closed");
            }
            return delegate.canonicalPath(path);
        }

        @Override
        public Attributes stat(String path) throws IOException {
            if (!isOpen()) {
                throw new IOException("stat(" + path + ") client is closed");
            }
            return delegate.stat(path);
        }

        @Override
        public Attributes lstat(String path) throws IOException {
            if (!isOpen()) {
                throw new IOException("lstat(" + path + ") client is closed");
            }
            return delegate.lstat(path);
        }

        @Override
        public Attributes stat(Handle handle) throws IOException {
            if (!isOpen()) {
                throw new IOException("stat(" + handle + ") client is closed");
            }
            return delegate.stat(handle);
        }

        @Override
        public void setStat(String path, Attributes attributes) throws IOException {
            if (!isOpen()) {
                throw new IOException("setStat(" + path + ")[" + attributes + "] client is closed");
            }
            delegate.setStat(path, attributes);
        }

        @Override
        public void setStat(Handle handle, Attributes attributes) throws IOException {
            if (!isOpen()) {
                throw new IOException("setStat(" + handle + ")[" + attributes + "] client is closed");
            }
            delegate.setStat(handle, attributes);
        }

        @Override
        public String readLink(String path) throws IOException {
            if (!isOpen()) {
                throw new IOException("readLink(" + path + ") client is closed");
            }
            return delegate.readLink(path);
        }

        @Override
        public void symLink(String linkPath, String targetPath) throws IOException {
            if (!isOpen()) {
                throw new IOException("symLink(" + linkPath + " => " + targetPath + ") client is closed");
            }
            delegate.symLink(linkPath, targetPath);
        }

        @Override
        public Iterable<DirEntry> readDir(String path) throws IOException {
            if (!isOpen()) {
                throw new IOException("readDir(" + path + ") client is closed");
            }
            return delegate.readDir(path);
        }

        @Override
        public InputStream read(String path) throws IOException {
            return read(path, readSize);
        }

        @Override
        public InputStream read(String path, OpenMode... mode) throws IOException {
            return read(path, readSize, mode);
        }

        @Override
        public InputStream read(String path, Collection<OpenMode> mode) throws IOException {
            return read(path, readSize, mode);
        }

        @Override
        public InputStream read(String path, int bufferSize, Collection<OpenMode> mode) throws IOException {
            if (!isOpen()) {
                throw new IOException("read(" + path + ")[" + mode + "] size=" + bufferSize + ": client is closed");
            }
            return delegate.read(path, bufferSize, mode);
        }

        @Override
        public OutputStream write(String path) throws IOException {
            return write(path, writeSize);
        }

        @Override
        public OutputStream write(String path, OpenMode... mode) throws IOException {
            return write(path, writeSize, mode);
        }

        @Override
        public OutputStream write(String path, Collection<OpenMode> mode) throws IOException {
            return write(path, writeSize, mode);
        }

        @Override
        public OutputStream write(String path, int bufferSize, Collection<OpenMode> mode) throws IOException {
            if (!isOpen()) {
                throw new IOException("write(" + path + ")[" + mode + "] size=" + bufferSize + ": client is closed");
            }
            return delegate.write(path, bufferSize, mode);
        }

        @Override
        public void link(String linkPath, String targetPath, boolean symbolic) throws IOException {
            if (!isOpen()) {
                throw new IOException(
                        "link(" + linkPath + " => " + targetPath + "] symbolic=" + symbolic + ": client is closed");
            }
            delegate.link(linkPath, targetPath, symbolic);
        }

        @Override
        public void lock(Handle handle, long offset, long length, int mask) throws IOException {
            if (!isOpen()) {
                throw new IOException(
                        "lock(" + handle + ")[offset=" + offset + ", length=" + length + ", mask=0x" + Integer.toHexString(mask)
                                      + "] client is closed");
            }
            delegate.lock(handle, offset, length, mask);
        }

        @Override
        public void unlock(Handle handle, long offset, long length) throws IOException {
            if (!isOpen()) {
                throw new IOException("unlock" + handle + ")[offset=" + offset + ", length=" + length + "] client is closed");
            }
            delegate.unlock(handle, offset, length);
        }

        @Override
        public int send(int cmd, Buffer buffer) throws IOException {
            if (!isOpen()) {
                throw new IOException("send(cmd=" + SftpConstants.getCommandMessageName(cmd) + ") client is closed");
            }

            if (delegate instanceof RawSftpClient) {
                return ((RawSftpClient) delegate).send(cmd, buffer);
            } else {
                throw new StreamCorruptedException(
                        "send(cmd=" + SftpConstants.getCommandMessageName(cmd) + ") delegate is not a "
                                                   + RawSftpClient.class.getSimpleName());
            }
        }

        @Override
        public Buffer receive(int id) throws IOException {
            if (!isOpen()) {
                throw new IOException("receive(id=" + id + ") client is closed");
            }

            if (delegate instanceof RawSftpClient) {
                return ((RawSftpClient) delegate).receive(id);
            } else {
                throw new StreamCorruptedException(
                        "receive(id=" + id + ") delegate is not a " + RawSftpClient.class.getSimpleName());
            }
        }

        @Override
        public Buffer receive(int id, long timeout) throws IOException {
            if (!isOpen()) {
                throw new IOException("receive(id=" + id + ", timeout=" + timeout + ") client is closed");
            }

            if (delegate instanceof RawSftpClient) {
                return ((RawSftpClient) delegate).receive(id, timeout);
            } else {
                throw new StreamCorruptedException(
                        "receive(id=" + id + ", timeout=" + timeout + ") delegate is not a "
                                                   + RawSftpClient.class.getSimpleName());
            }
        }

        @Override
        public Buffer receive(int id, Duration timeout) throws IOException {
            if (!isOpen()) {
                throw new IOException("receive(id=" + id + ", timeout=" + timeout + ") client is closed");
            }

            if (delegate instanceof RawSftpClient) {
                return ((RawSftpClient) delegate).receive(id, timeout);
            } else {
                throw new StreamCorruptedException(
                        "receive(id=" + id + ", timeout=" + timeout + ") delegate is not a "
                                                   + RawSftpClient.class.getSimpleName());
            }
        }
    }

    public static class DefaultUserPrincipalLookupService extends UserPrincipalLookupService {
        public static final DefaultUserPrincipalLookupService INSTANCE = new DefaultUserPrincipalLookupService();

        public DefaultUserPrincipalLookupService() {
            super();
        }

        @Override
        public UserPrincipal lookupPrincipalByName(String name) throws IOException {
            return new DefaultUserPrincipal(name);
        }

        @Override
        public GroupPrincipal lookupPrincipalByGroupName(String group) throws IOException {
            return new DefaultGroupPrincipal(group);
        }
    }

    public static class DefaultUserPrincipal implements UserPrincipal {

        private final String name;

        public DefaultUserPrincipal(String name) {
            this.name = Objects.requireNonNull(name, "name is null");
        }

        @Override
        public final String getName() {
            return name;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            DefaultUserPrincipal that = (DefaultUserPrincipal) o;
            return Objects.equals(this.getName(), that.getName());
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(getName());
        }

        @Override
        public String toString() {
            return getName();
        }
    }

    public static class DefaultGroupPrincipal extends DefaultUserPrincipal implements GroupPrincipal {
        public DefaultGroupPrincipal(String name) {
            super(name);
        }
    }
}
