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

package org.apache.sshd.common.file.nonefs;

import java.io.IOException;
import java.net.URI;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessMode;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.spi.FileSystemProvider;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Provides an &quot;empty&quot; {@link FileSystemProvider} that has no files of any type.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class NoneFileSystemProvider extends FileSystemProvider {
    public static final String SCHEME = "none";

    public static final NoneFileSystemProvider INSTANCE = new NoneFileSystemProvider();

    public NoneFileSystemProvider() {
        super();
    }

    @Override
    public String getScheme() {
        return SCHEME;
    }

    @Override
    public FileSystem newFileSystem(URI uri, Map<String, ?> env) throws IOException {
        return getFileSystem(uri);
    }

    @Override
    public FileSystem getFileSystem(URI uri) {
        if (!Objects.equals(getScheme(), uri.getScheme())) {
            throw new IllegalArgumentException("Mismatched FS scheme");
        }

        return NoneFileSystem.INSTANCE;
    }

    @Override
    public Path getPath(URI uri) {
        if (!Objects.equals(getScheme(), uri.getScheme())) {
            throw new IllegalArgumentException("Mismatched FS scheme");
        }

        throw new UnsupportedOperationException("No paths available");
    }

    @Override
    public SeekableByteChannel newByteChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs)
            throws IOException {
        throw new NoSuchFileException(path.toString());
    }

    @Override
    public DirectoryStream<Path> newDirectoryStream(Path dir, Filter<? super Path> filter) throws IOException {
        throw new NoSuchFileException(dir.toString());
    }

    @Override
    public void createDirectory(Path dir, FileAttribute<?>... attrs) throws IOException {
        throw new NoSuchFileException(dir.toString());
    }

    @Override
    public void delete(Path path) throws IOException {
        throw new NoSuchFileException(path.toString());
    }

    @Override
    public void copy(Path source, Path target, CopyOption... options) throws IOException {
        throw new NoSuchFileException(source.toString(), target.toString(), "N/A");

    }

    @Override
    public void move(Path source, Path target, CopyOption... options) throws IOException {
        throw new NoSuchFileException(source.toString(), target.toString(), "N/A");
    }

    @Override
    public boolean isSameFile(Path path1, Path path2) throws IOException {
        throw new NoSuchFileException(path1.toString(), path2.toString(), "N/A");
    }

    @Override
    public boolean isHidden(Path path) throws IOException {
        throw new NoSuchFileException(path.toString());
    }

    @Override
    public FileStore getFileStore(Path path) throws IOException {
        throw new NoSuchFileException(path.toString());
    }

    @Override
    public void checkAccess(Path path, AccessMode... modes) throws IOException {
        throw new NoSuchFileException(path.toString());
    }

    @Override
    public <V extends FileAttributeView> V getFileAttributeView(Path path, Class<V> type, LinkOption... options) {
        return null;
    }

    @Override
    public <A extends BasicFileAttributes> A readAttributes(Path path, Class<A> type, LinkOption... options)
            throws IOException {
        throw new NoSuchFileException(path.toString());
    }

    @Override
    public Map<String, Object> readAttributes(Path path, String attributes, LinkOption... options) throws IOException {
        throw new NoSuchFileException(path.toString());
    }

    @Override
    public void setAttribute(Path path, String attribute, Object value, LinkOption... options) throws IOException {
        throw new NoSuchFileException(path.toString());
    }
}
