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
import java.nio.file.FileSystemException;
import java.nio.file.FileSystemNotFoundException;
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

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;

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
        Path localPath2 = ensureDirectory(path).toRealPath();

        RootedFileSystem rootedFs=null;
        synchronized (fileSystems) {
            if (!this.fileSystems.containsKey(localPath2)) {
                rootedFs = new RootedFileSystem(this, path, env);
                this.fileSystems.put(localPath2, rootedFs);
            }
        }

        // do all the throwing outside the synchronized block to minimize its lock time
        if (rootedFs == null) {
            throw new FileSystemAlreadyExistsException("newFileSystem(" + uri + ") already mapped " + localPath2);
        }

        return rootedFs;
    }

    @Override
    public FileSystem getFileSystem(URI uri) {
        try {
            FileSystem fileSystem = getFileSystem(uriToPath(uri));
            if (fileSystem == null) {
                throw new FileSystemNotFoundException(uri.toString());
            }

            return fileSystem;
        } catch(IOException e) {
            FileSystemNotFoundException err = new FileSystemNotFoundException(uri.toString());
            err.initCause(e);
            throw err;
        }
    }

    @Override
    public FileSystem newFileSystem(Path path, Map<String, ?> env) throws IOException {
        return new RootedFileSystem(this, ensureDirectory(path), env);
    }

    protected Path uriToPath(URI uri) {
        String scheme = uri.getScheme(), expected = getScheme();
        if ((scheme == null) || (!scheme.equalsIgnoreCase(expected))) {
            throw new IllegalArgumentException("URI scheme (" + scheme + ") is not '" + expected + "'");
        }

        String root = uri.getRawSchemeSpecificPart();
        int i = root.indexOf("!/");
        if (i != -1) {
            root = root.substring(0, i);
        }

        try {
            return Paths.get(new URI(root)).toAbsolutePath();
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(root + ": " + e.getMessage(), e);
        }
    }

    private static Path ensureDirectory(Path path) {
        return IoUtils.ensureDirectory(path, IoUtils.getLinkOptions(false));
    }

    @Override
    public Path getPath(URI uri) {
        String str = uri.getSchemeSpecificPart();
        int i = str.indexOf("!/");
        if (i == -1) {
            throw new IllegalArgumentException("URI: " + uri + " does not contain path info - e.g., root:file://foo/bar!/");
        }

        FileSystem fs = getFileSystem(uri);
        String subPath = str.substring(i + 1);
        return fs.getPath(subPath);
    }

    @Override
    public InputStream newInputStream(Path path, OpenOption... options) throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        return p.newInputStream(r, options);
    }

    @Override
    public OutputStream newOutputStream(Path path, OpenOption... options) throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        return p.newOutputStream(r, options);
    }

    @Override
    public FileChannel newFileChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs) throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        return p.newFileChannel(r, options, attrs);
    }

    @Override
    public AsynchronousFileChannel newAsynchronousFileChannel(Path path, Set<? extends OpenOption> options, ExecutorService executor, FileAttribute<?>... attrs) throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        return p.newAsynchronousFileChannel(r, options, executor, attrs);
    }

    @Override
    public SeekableByteChannel newByteChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs) throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        return p.newByteChannel(path, options, attrs);
    }

    @Override
    public DirectoryStream<Path> newDirectoryStream(Path dir, DirectoryStream.Filter<? super Path> filter) throws IOException {
        Path r = unroot(dir);
        FileSystemProvider p = provider(r);
        return p.newDirectoryStream(r, filter);
    }

    @Override
    public void createDirectory(Path dir, FileAttribute<?>... attrs) throws IOException {
        Path r = unroot(dir);
        FileSystemProvider p = provider(r);
        p.createDirectory(r, attrs);
    }

    @Override
    public void createSymbolicLink(Path link, Path target, FileAttribute<?>... attrs) throws IOException {
        Path l = unroot(link);
        Path t = unroot(target, false);
        FileSystemProvider p = provider(l);
        p.createSymbolicLink(l, t, attrs);
    }

    @Override
    public void createLink(Path link, Path existing) throws IOException {
        Path l = unroot(link);
        Path e = unroot(existing);
        FileSystemProvider p = provider(l);
        p.createLink(l, e);
    }

    @Override
    public void delete(Path path) throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        p.delete(r);
    }

    @Override
    public boolean deleteIfExists(Path path) throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        return p.deleteIfExists(r);
    }

    @Override
    public Path readSymbolicLink(Path link) throws IOException {
        Path r = unroot(link);
        FileSystemProvider p = provider(r);
        return root(link.getFileSystem(), p.readSymbolicLink(r));

    }

    @Override
    public void copy(Path source, Path target, CopyOption... options) throws IOException {
        Path s = unroot(source);
        Path t = unroot(target);
        FileSystemProvider p = provider(s);
        p.copy(s, t, options);
    }

    @Override
    public void move(Path source, Path target, CopyOption... options) throws IOException {
        Path s = unroot(source);
        Path t = unroot(target);
        FileSystemProvider p = provider(s);
        p.move(s, t, options);
    }

    @Override
    public boolean isSameFile(Path path, Path path2) throws IOException {
        Path r = unroot(path);
        Path r2 = unroot(path2);
        FileSystemProvider p = provider(r);
        return p.isSameFile(r, r2);
    }

    @Override
    public boolean isHidden(Path path) throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        return p.isHidden(r);
    }

    @Override
    public FileStore getFileStore(Path path) throws IOException {
        FileSystem fileSystem = getFileSystem(path);
        if (fileSystem == null) {
            throw new FileSystemNotFoundException(path.toString());
        }

        Iterable<FileStore> stores = fileSystem.getFileStores();
        if (stores == null) {
            throw new FileSystemException(path.toString(), path.toString(), "No stores");
        }
        
        for (FileStore s : stores) {
            return s;
        }

        throw new FileSystemException(path.toString(), path.toString(), "empty stores");
    }

    protected RootedFileSystem getFileSystem(Path path) throws IOException {
        try {
            Path real = path.toRealPath();
            synchronized (fileSystems) {
                return fileSystems.get(real);
            }
        } catch (IOException e) {
            FileSystemNotFoundException err = new FileSystemNotFoundException(path.toString());
            err.initCause(e);
            throw err;
        }
    }

    @Override
    public void checkAccess(Path path, AccessMode... modes) throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        p.checkAccess(r, modes);
    }

    @Override
    public <V extends FileAttributeView> V getFileAttributeView(Path path, Class<V> type, LinkOption... options) {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        return p.getFileAttributeView(r, type, options);
    }

    @Override
    public <A extends BasicFileAttributes> A readAttributes(Path path, Class<A> type, LinkOption... options) throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        return p.readAttributes(r, type, options);
    }

    @Override
    public Map<String, Object> readAttributes(Path path, String attributes, LinkOption... options) throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        return p.readAttributes(r, attributes, options);
    }

    @Override
    public void setAttribute(Path path, String attribute, Object value, LinkOption... options) throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        p.setAttribute(r, attribute, value, options);
    }

    private static FileSystemProvider provider(Path path) {
        FileSystem fs = path.getFileSystem();
        return fs.provider();
    }

    private static Path root(FileSystem  fs, Path nat) {
        RootedFileSystem rfs = (RootedFileSystem) fs;
        if (nat.isAbsolute()) {
            Path root = rfs.getRoot();
            Path rel = root.relativize(nat);
            return rfs.getPath("/" + rel.toString());
        } else {
            return rfs.getPath(nat.toString());
        }
    }

    private static Path unroot(Path path) {
        return unroot(path, true);
    }

    private static Path unroot(Path path, boolean absolute) {
        ValidateUtils.checkNotNull(path, "No path to unroot", GenericUtils.EMPTY_OBJECT_ARRAY);
        if (!(path instanceof RootedPath)) {
            throw new ProviderMismatchException("unroot(" + path + ") is not a " + RootedPath.class.getSimpleName()
                                              + " but rather a " + path.getClass().getSimpleName());
        }

        RootedPath p = (RootedPath) path;
        if (absolute || p.isAbsolute()) {
            Path absPath = p.toAbsolutePath();
            String r = absPath.toString();
            RootedFileSystem rfs = p.getFileSystem();
            Path root = rfs.getRoot();
            return root.resolve(r.substring(1));
        } else {
            RootedPath fileName = p.getFileName();
            RootedPath root = fileName.getRoot();
            RootedFileSystem rfs = root.getFileSystem();
            return rfs.getPath(p.toString());
        }
    }

}
