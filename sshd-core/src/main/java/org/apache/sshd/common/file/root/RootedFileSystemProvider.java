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
package org.apache.sshd.common.file.root;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessMode;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.ProviderMismatchException;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.spi.FileSystemProvider;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;

import org.apache.sshd.common.util.IoUtils;

/**
 * File system provider which provides a rooted file system.
 * The file system only gives access to files under the root directory.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class RootedFileSystemProvider extends FileSystemProvider {
    private final Map<Path, RootedFileSystem> fileSystems = new HashMap<>();

    public RootedFileSystemProvider() {
        super();
    }

    @Override
    public String getScheme() {
        return "root";
    }

    @Override
    public FileSystem newFileSystem(URI uri, Map<String, ?> env) throws IOException {
        Path path = uriToPath(uri);
        synchronized (fileSystems)
        {
            Path localPath2 = null;
            if (ensureDirectory(path))
            {
                localPath2 = path.toRealPath();
                if (this.fileSystems.containsKey(localPath2)) {
                    throw new FileSystemAlreadyExistsException();
                }
            }
            RootedFileSystem rootedFs = new RootedFileSystem(this, path, env);
            this.fileSystems.put(localPath2, rootedFs);
            return rootedFs;
        }
    }

    @Override
    public FileSystem getFileSystem(URI uri) {
        synchronized (fileSystems) {
            RootedFileSystem fileSystem = null;
            try {
                fileSystem = fileSystems.get(uriToPath(uri).toRealPath());
            } catch (IOException ignore) {
                // ignored
            }
            if (fileSystem == null) {
                throw new FileSystemNotFoundException(uri.toString());
            }
            return fileSystem;
        }
    }

    @Override
    public FileSystem newFileSystem(Path path, Map<String, ?> env) throws IOException {
        ensureDirectory(path);
        return new RootedFileSystem(this, path, env);
    }

    protected Path uriToPath(URI uri) {
        String scheme = uri.getScheme();
        if ((scheme == null) || (!scheme.equalsIgnoreCase(getScheme()))) {
            throw new IllegalArgumentException("URI scheme is not '" + getScheme() + "'");
        }
        try {
            String root = uri.getRawSchemeSpecificPart();
            int i = root.indexOf("!/");
            if (i != -1) {
                root = root.substring(0, i);
            }
            return Paths.get(new URI(root)).toAbsolutePath();
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    private boolean ensureDirectory(Path path) {
        if (!Files.isDirectory(path, IoUtils.getLinkOptions(false))) {
            throw new UnsupportedOperationException("Not a directory: " + path);
        }
        return true;
    }

    @Override
    public Path getPath(URI uri) {
        String str = uri.getSchemeSpecificPart();
        int i = str.indexOf("!/");
        if (i == -1) {
            throw new IllegalArgumentException("URI: " + uri + " does not contain path info ex. root:file://foo/bar!/");
        }
        return getFileSystem(uri).getPath(str.substring(i + 1));
    }

    @Override
    public InputStream newInputStream(Path path, OpenOption... options) throws IOException {
        Path r = unroot(path);
        return provider(r).newInputStream(r, options);
    }

    @Override
    public OutputStream newOutputStream(Path path, OpenOption... options) throws IOException {
        Path r = unroot(path);
        return provider(r).newOutputStream(r, options);
    }

    @Override
    public FileChannel newFileChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs) throws IOException {
        Path r = unroot(path);
        return provider(r).newFileChannel(r, options, attrs);
    }

    @Override
    public AsynchronousFileChannel newAsynchronousFileChannel(Path path, Set<? extends OpenOption> options, ExecutorService executor, FileAttribute<?>... attrs) throws IOException {
        Path r = unroot(path);
        return provider(r).newAsynchronousFileChannel(r, options, executor, attrs);
    }

    @Override
    public SeekableByteChannel newByteChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs) throws IOException {
        Path r = unroot(path);
        return provider(r).newByteChannel(path, options, attrs);
    }

    @Override
    public DirectoryStream<Path> newDirectoryStream(Path dir, DirectoryStream.Filter<? super Path> filter) throws IOException {
        Path r = unroot(dir);
        return provider(r).newDirectoryStream(r, filter);
    }

    @Override
    public void createDirectory(Path dir, FileAttribute<?>... attrs) throws IOException {
        Path r = unroot(dir);
        provider(r).createDirectory(r, attrs);
    }

    @Override
    public void createSymbolicLink(Path link, Path target, FileAttribute<?>... attrs) throws IOException {
        Path l = unroot(link);
        Path t = unroot(target, false);
        provider(l).createSymbolicLink(l, t, attrs);
    }

    @Override
    public void createLink(Path link, Path existing) throws IOException {
        Path l = unroot(link);
        Path e = unroot(existing);
        provider(l).createLink(l, e);
    }

    @Override
    public void delete(Path path) throws IOException {
        Path r = unroot(path);
        provider(r).delete(r);
    }

    @Override
    public boolean deleteIfExists(Path path) throws IOException {
        Path r = unroot(path);
        return provider(r).deleteIfExists(r);
    }

    @Override
    public Path readSymbolicLink(Path link) throws IOException {
        Path r = unroot(link);
        return root(link.getFileSystem(), provider(r).readSymbolicLink(r));

    }

    @Override
    public void copy(Path source, Path target, CopyOption... options) throws IOException {
        Path s = unroot(source);
        Path t = unroot(target);
        provider(s).copy(s, t, options);
    }

    @Override
    public void move(Path source, Path target, CopyOption... options) throws IOException {
        Path s = unroot(source);
        Path t = unroot(target);
        provider(s).move(s, t, options);
    }

    @Override
    public boolean isSameFile(Path path, Path path2) throws IOException {
        Path r = unroot(path);
        Path r2 = unroot(path2);
        return provider(r).isSameFile(r, r2);
    }

    @Override
    public boolean isHidden(Path path) throws IOException {
        Path r = unroot(path);
        return provider(r).isHidden(r);
    }

    @Override
    public FileStore getFileStore(Path path) throws IOException {
        throw new UnsupportedOperationException("getFileStore(" + path + ") N/A");
    }

    @Override
    public void checkAccess(Path path, AccessMode... modes) throws IOException {
        Path r = unroot(path);
        provider(r).checkAccess(r, modes);
    }

    @Override
    public <V extends FileAttributeView> V getFileAttributeView(Path path, Class<V> type, LinkOption... options) {
        Path r = unroot(path);
        return provider(r).getFileAttributeView(r, type, options);
    }

    @Override
    public <A extends BasicFileAttributes> A readAttributes(Path path, Class<A> type, LinkOption... options) throws IOException {
        Path r = unroot(path);
        return provider(r).readAttributes(r, type, options);
    }

    @Override
    public Map<String, Object> readAttributes(Path path, String attributes, LinkOption... options) throws IOException {
        Path r = unroot(path);
        return provider(r).readAttributes(r, attributes, options);
    }

    @Override
    public void setAttribute(Path path, String attribute, Object value, LinkOption... options) throws IOException {
        Path r = unroot(path);
        provider(r).setAttribute(r, attribute, value, options);
    }

    private FileSystemProvider provider(Path path) {
        return path.getFileSystem().provider();
    }

    private Path root(FileSystem  fs, Path nat) {
        RootedFileSystem rfs = (RootedFileSystem) fs;
        if (nat.isAbsolute()) {
            return rfs.getPath("/" + rfs.getRoot().relativize(nat).toString());
        } else {
            return rfs.getPath(nat.toString());
        }
    }

    private Path unroot(Path path) {
        return unroot(path, true);
    }

    private Path unroot(Path path, boolean absolute) {
        if (path == null) {
            throw new NullPointerException();
        }
        if (!(path instanceof RootedPath)) {
            throw new ProviderMismatchException();
        }
        RootedPath p = (RootedPath) path;
        if (absolute || p.isAbsolute()) {
            String r = p.toAbsolutePath().toString();
            return p.getFileSystem().getRoot().resolve(r.substring(1));
        } else {
            return p.getFileName().getRoot().getFileSystem().getPath(p.toString());
        }
    }

}
