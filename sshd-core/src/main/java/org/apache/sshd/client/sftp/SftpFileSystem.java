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
package org.apache.sshd.client.sftp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.ClientSession;
import org.apache.sshd.client.SftpClient;
import org.apache.sshd.common.file.util.BaseFileSystem;
import org.apache.sshd.common.file.util.ImmutableList;

public class SftpFileSystem extends BaseFileSystem<SftpPath> {

    private final ClientSession session;
    private final Queue<SftpClient> pool;
    private final ThreadLocal<Wrapper> wrappers = new ThreadLocal<>();
    private SftpPath defaultDir;

    public SftpFileSystem(SftpFileSystemProvider provider, ClientSession session) throws IOException {
        super(provider);
        this.session = session;
        this.pool = new LinkedBlockingQueue<>(8);
        try (SftpClient client = getClient()) {
            defaultDir = getPath(client.canonicalPath("."));
        }
    }

    @Override
    protected SftpPath create(String root, ImmutableList<String> names) {
        return new SftpPath(this, root, names);
    }

    public ClientSession getSession() {
        return session;
    }

    @SuppressWarnings("synthetic-access")
    public SftpClient getClient() throws IOException {
        Wrapper wrapper = wrappers.get();
        if (wrapper == null) {
            while (wrapper == null) {
                SftpClient client = pool.poll();
                if (client == null) {
                    client = session.createSftpClient();
                }
                if (!client.isClosing()) {
                    wrapper = new Wrapper(client);
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
        session.close(true);
    }

    @Override
    public boolean isOpen() {
        return !session.isClosing();
    }

    @Override
    public Set<String> supportedFileAttributeViews() {
        Set<String> set = new HashSet<>();
        set.addAll(Arrays.asList("basic", "posix", "owner"));
        return Collections.unmodifiableSet(set);
    }

    @Override
    public UserPrincipalLookupService getUserPrincipalLookupService() {
        return new DefaultUserPrincipalLookupService();
    }

    @Override
    public SftpPath getDefaultDir() {
        return defaultDir;
    }

    private class Wrapper implements SftpClient {

        private final SftpClient delegate;
        private final AtomicInteger count = new AtomicInteger(1);

        private Wrapper(SftpClient delegate) {
            this.delegate = delegate;
        }

        @Override
        public int getVersion() {
            return delegate.getVersion();
        }

        @Override
        public boolean isClosing() {
            return false;
        }

        @SuppressWarnings("synthetic-access")
        @Override
        public void close() throws IOException {
            if (count.decrementAndGet() == 0) {
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
        public Handle open(String path, Collection<OpenMode> options) throws IOException {
            return delegate.open(path, options);
        }

        @Override
        public void close(Handle handle) throws IOException {
            delegate.close(handle);
        }

        @Override
        public void remove(String path) throws IOException {
            delegate.remove(path);
        }

        @Override
        public void rename(String oldPath, String newPath) throws IOException {
            delegate.rename(oldPath, newPath);
        }

        @Override
        public void rename(String oldPath, String newPath, CopyMode... options) throws IOException {
            delegate.rename(oldPath, newPath, options);
        }

        @Override
        public int read(Handle handle, long fileOffset, byte[] dst, int dstoff, int len) throws IOException {
            return delegate.read(handle, fileOffset, dst, dstoff, len);
        }

        @Override
        public void write(Handle handle, long fileOffset, byte[] src, int srcoff, int len) throws IOException {
            delegate.write(handle, fileOffset, src, srcoff, len);
        }

        @Override
        public void mkdir(String path) throws IOException {
            delegate.mkdir(path);
        }

        @Override
        public void rmdir(String path) throws IOException {
            delegate.rmdir(path);
        }

        @Override
        public Handle openDir(String path) throws IOException {
            return delegate.openDir(path);
        }

        @Override
        public DirEntry[] readDir(Handle handle) throws IOException {
            return delegate.readDir(handle);
        }

        @Override
        public String canonicalPath(String canonical) throws IOException {
            return delegate.canonicalPath(canonical);
        }

        @Override
        public Attributes stat(String path) throws IOException {
            return delegate.stat(path);
        }

        @Override
        public Attributes lstat(String path) throws IOException {
            return delegate.lstat(path);
        }

        @Override
        public Attributes stat(Handle handle) throws IOException {
            return delegate.stat(handle);
        }

        @Override
        public void setStat(String path, Attributes attributes) throws IOException {
            delegate.setStat(path, attributes);
        }

        @Override
        public void setStat(Handle handle, Attributes attributes) throws IOException {
            delegate.setStat(handle, attributes);
        }

        @Override
        public String readLink(String path) throws IOException {
            return delegate.readLink(path);
        }

        @Override
        public void symLink(String linkPath, String targetPath) throws IOException {
            delegate.symLink(linkPath, targetPath);
        }

        @Override
        public Iterable<DirEntry> readDir(String path) throws IOException {
            return delegate.readDir(path);
        }

        @Override
        public InputStream read(String path) throws IOException {
            return delegate.read(path);
        }

        @Override
        public InputStream read(String path, Collection<OpenMode> mode) throws IOException {
            return delegate.read(path, mode);
        }

        @Override
        public OutputStream write(String path) throws IOException {
            return delegate.write(path);
        }

        @Override
        public OutputStream write(String path, Collection<OpenMode> mode) throws IOException {
            return delegate.write(path, mode);
        }

        @Override
        public void link(String linkPath, String targetPath, boolean symbolic) throws IOException {
            delegate.link(linkPath, targetPath, symbolic);
        }

        @Override
        public void lock(Handle handle, long offset, long length, int mask) throws IOException {
            delegate.lock(handle, offset, length, mask);
        }

        @Override
        public void unlock(Handle handle, long offset, long length) throws IOException {
            delegate.unlock(handle, offset, length);
        }
    }

    protected static class DefaultUserPrincipalLookupService extends UserPrincipalLookupService {

        @Override
        public UserPrincipal lookupPrincipalByName(String name) throws IOException {
            return new DefaultUserPrincipal(name);
        }

        @Override
        public GroupPrincipal lookupPrincipalByGroupName(String group) throws IOException {
            return new DefaultGroupPrincipal(group);
        }
    }

    protected static class DefaultUserPrincipal implements UserPrincipal {

        private final String name;

        public DefaultUserPrincipal(String name) {
            if (name == null) {
                throw new IllegalArgumentException("name is null");
            }
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            DefaultUserPrincipal that = (DefaultUserPrincipal) o;
            return name.equals(that.name);
        }

        @Override
        public int hashCode() {
            return name.hashCode();
        }

        @Override
        public String toString() {
            return name;
        }
    }

    protected static class DefaultGroupPrincipal extends DefaultUserPrincipal implements GroupPrincipal {

        public DefaultGroupPrincipal(String name) {
            super(name);
        }

    }

}
