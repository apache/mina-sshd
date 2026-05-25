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
import java.net.URI;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessMode;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.spi.FileSystemProvider;
import java.util.Map;
import java.util.Set;

import org.apache.sshd.sftp.common.SftpConstants;

/**
 * SPI-registered SFTP file system provider using a singleton instance.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpFileSystemProviderFacade extends FileSystemProvider {

    private static final class DefaultSftpFileSystemSingleton {
        static final SftpFileSystemProvider INSTANCE = new SftpFileSystemProvider();

        private DefaultSftpFileSystemSingleton() {
            // No instantiation
        }
    }

    public SftpFileSystemProviderFacade() {
        // Nothing
    }

    @Override
    public String getScheme() {
        return SftpConstants.SFTP_SUBSYSTEM_NAME;
    }

    @Override
    public FileSystem newFileSystem(URI uri, Map<String, ?> env) throws IOException {
        return DefaultSftpFileSystemSingleton.INSTANCE.newFileSystem(uri, env);
    }

    @Override
    public FileSystem getFileSystem(URI uri) {
        return DefaultSftpFileSystemSingleton.INSTANCE.getFileSystem(uri);
    }

    @Override
    public Path getPath(URI uri) {
        return DefaultSftpFileSystemSingleton.INSTANCE.getPath(uri);
    }

    @Override
    public SeekableByteChannel newByteChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs)
            throws IOException {
        return DefaultSftpFileSystemSingleton.INSTANCE.newByteChannel(path, options, attrs);
    }

    @Override
    public FileChannel newFileChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs)
            throws IOException {
        return DefaultSftpFileSystemSingleton.INSTANCE.newFileChannel(path, options, attrs);
    }

    @Override
    public InputStream newInputStream(Path path, OpenOption... options) throws IOException {
        return DefaultSftpFileSystemSingleton.INSTANCE.newInputStream(path, options);
    }

    @Override
    public OutputStream newOutputStream(Path path, OpenOption... options) throws IOException {
        return DefaultSftpFileSystemSingleton.INSTANCE.newOutputStream(path, options);
    }

    @Override
    public DirectoryStream<Path> newDirectoryStream(Path dir, Filter<? super Path> filter) throws IOException {
        return DefaultSftpFileSystemSingleton.INSTANCE.newDirectoryStream(dir, filter);
    }

    @Override
    public void createSymbolicLink(Path link, Path target, FileAttribute<?>... attrs) throws IOException {
        DefaultSftpFileSystemSingleton.INSTANCE.createSymbolicLink(link, target, attrs);
    }

    @Override
    public Path readSymbolicLink(Path link) throws IOException {
        return DefaultSftpFileSystemSingleton.INSTANCE.readSymbolicLink(link);
    }

    @Override
    public void createDirectory(Path dir, FileAttribute<?>... attrs) throws IOException {
        DefaultSftpFileSystemSingleton.INSTANCE.createDirectory(dir, attrs);
    }

    @Override
    public void delete(Path path) throws IOException {
        DefaultSftpFileSystemSingleton.INSTANCE.delete(path);
    }

    @Override
    public void copy(Path source, Path target, CopyOption... options) throws IOException {
        DefaultSftpFileSystemSingleton.INSTANCE.copy(source, target, options);
    }

    @Override
    public void move(Path source, Path target, CopyOption... options) throws IOException {
        DefaultSftpFileSystemSingleton.INSTANCE.move(source, target, options);
    }

    @Override
    public boolean isSameFile(Path path, Path path2) throws IOException {
        return DefaultSftpFileSystemSingleton.INSTANCE.isSameFile(path, path2);
    }

    @Override
    public boolean isHidden(Path path) throws IOException {
        return DefaultSftpFileSystemSingleton.INSTANCE.isHidden(path);
    }

    @Override
    public FileStore getFileStore(Path path) throws IOException {
        return DefaultSftpFileSystemSingleton.INSTANCE.getFileStore(path);
    }

    @Override
    public void checkAccess(Path path, AccessMode... modes) throws IOException {
        DefaultSftpFileSystemSingleton.INSTANCE.checkAccess(path, modes);
    }

    @Override
    public <V extends FileAttributeView> V getFileAttributeView(Path path, Class<V> type, LinkOption... options) {
        return DefaultSftpFileSystemSingleton.INSTANCE.getFileAttributeView(path, type, options);
    }

    @Override
    public <A extends BasicFileAttributes> A readAttributes(Path path, Class<A> type, LinkOption... options)
            throws IOException {
        return DefaultSftpFileSystemSingleton.INSTANCE.readAttributes(path, type, options);
    }

    @Override
    public Map<String, Object> readAttributes(Path path, String attributes, LinkOption... options) throws IOException {
        return DefaultSftpFileSystemSingleton.INSTANCE.readAttributes(path, attributes, options);
    }

    @Override
    public void setAttribute(Path path, String attribute, Object value, LinkOption... options) throws IOException {
        DefaultSftpFileSystemSingleton.INSTANCE.setAttribute(path, attribute, value, options);
    }

}
