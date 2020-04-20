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
import java.nio.file.InvalidPathException;
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
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutorService;

import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * File system provider which provides a rooted file system. The file system only gives access to files under the root
 * directory.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class RootedFileSystemProvider extends FileSystemProvider {
    protected final Logger log;
    private final Map<Path, RootedFileSystem> fileSystems = new HashMap<>();

    public RootedFileSystemProvider() {
        log = LoggerFactory.getLogger(getClass());
    }

    @Override
    public String getScheme() {
        return "root";
    }

    @Override
    public FileSystem newFileSystem(URI uri, Map<String, ?> env) throws IOException {
        return newFileSystem(uri, uriToPath(uri), env);
    }

    @Override
    public FileSystem getFileSystem(URI uri) {
        return getFileSystem(uriToPath(uri));
    }

    @Override
    public FileSystem newFileSystem(Path path, Map<String, ?> env) throws IOException {
        return newFileSystem(path, path, env);
    }

    protected FileSystem newFileSystem(Object src, Path path, Map<String, ?> env) throws IOException {
        Path root = ensureDirectory(path).toRealPath();
        RootedFileSystem rootedFs = null;
        synchronized (fileSystems) {
            if (!this.fileSystems.containsKey(root)) {
                rootedFs = new RootedFileSystem(this, path, env);
                this.fileSystems.put(root, rootedFs);
            }
        }

        // do all the throwing outside the synchronized block to minimize its lock time
        if (rootedFs == null) {
            throw new FileSystemAlreadyExistsException("newFileSystem(" + src + ") already mapped " + root);
        }

        if (log.isTraceEnabled()) {
            log.trace("newFileSystem({}): {}", src, rootedFs);
        }

        return rootedFs;
    }

    protected Path uriToPath(URI uri) {
        String scheme = uri.getScheme();
        String expected = getScheme();
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
        return IoUtils.ensureDirectory(path, IoUtils.getLinkOptions(true));
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
        Path p = fs.getPath(subPath);
        if (log.isTraceEnabled()) {
            log.trace("getPath({}): {}", uri, p);
        }
        return p;
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
    public FileChannel newFileChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs)
            throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        return p.newFileChannel(r, options, attrs);
    }

    @Override
    public AsynchronousFileChannel newAsynchronousFileChannel(
            Path path, Set<? extends OpenOption> options, ExecutorService executor, FileAttribute<?>... attrs)
            throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        return p.newAsynchronousFileChannel(r, options, executor, attrs);
    }

    @Override
    public SeekableByteChannel newByteChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs)
            throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        return p.newByteChannel(r, options, attrs);
    }

    @Override
    public DirectoryStream<Path> newDirectoryStream(Path dir, DirectoryStream.Filter<? super Path> filter) throws IOException {
        Path r = unroot(dir);
        FileSystemProvider p = provider(r);
        return root(((RootedPath) dir).getFileSystem(), p.newDirectoryStream(r, filter));
    }

    protected DirectoryStream<Path> root(RootedFileSystem rfs, DirectoryStream<Path> ds) {
        return new DirectoryStream<Path>() {
            @Override
            public Iterator<Path> iterator() {
                return root(rfs, ds.iterator());
            }

            @Override
            public void close() throws IOException {
                ds.close();
            }
        };
    }

    protected Iterator<Path> root(RootedFileSystem rfs, Iterator<Path> iter) {
        return new Iterator<Path>() {
            @Override
            public boolean hasNext() {
                return iter.hasNext();
            }

            @Override
            public Path next() {
                return root(rfs, iter.next());
            }
        };
    }

    @Override
    public void createDirectory(Path dir, FileAttribute<?>... attrs) throws IOException {
        Path r = unroot(dir);
        FileSystemProvider p = provider(r);
        p.createDirectory(r, attrs);
    }

    @Override
    public void createSymbolicLink(Path link, Path target, FileAttribute<?>... attrs) throws IOException {
        createLink(link, target, true, attrs);
    }

    @Override
    public void createLink(Path link, Path existing) throws IOException {
        createLink(link, existing, false);
    }

    protected void createLink(Path link, Path target, boolean symLink, FileAttribute<?>... attrs) throws IOException {
        Path l = unroot(link);
        Path t = unroot(target);
        /*
         * For a symbolic link preserve the relative path
         */
        if (symLink && (!target.isAbsolute())) {
            RootedFileSystem rfs = ((RootedPath) target).getFileSystem();
            Path root = rfs.getRoot();
            t = root.relativize(t);
        }

        FileSystemProvider p = provider(l);
        if (symLink) {
            p.createSymbolicLink(l, t, attrs);
        } else {
            p.createLink(l, t);
        }

        if (log.isDebugEnabled()) {
            log.debug("createLink(symbolic={}) {} => {}", symLink, l, t);
        }
    }

    @Override
    public void delete(Path path) throws IOException {
        Path r = unroot(path);
        if (log.isTraceEnabled()) {
            log.trace("delete({}): {}", path, r);
        }
        FileSystemProvider p = provider(r);
        p.delete(r);
    }

    @Override
    public boolean deleteIfExists(Path path) throws IOException {
        Path r = unroot(path);
        if (log.isTraceEnabled()) {
            log.trace("deleteIfExists({}): {}", path, r);
        }
        FileSystemProvider p = provider(r);
        return p.deleteIfExists(r);
    }

    @Override
    public Path readSymbolicLink(Path link) throws IOException {
        Path r = unroot(link);
        FileSystemProvider p = provider(r);
        Path t = p.readSymbolicLink(r);
        Path target = root((RootedFileSystem) link.getFileSystem(), t);
        if (log.isTraceEnabled()) {
            log.trace("readSymbolicLink({})[{}]: {}[{}]", link, r, target, t);
        }
        return target;
    }

    @Override
    public void copy(Path source, Path target, CopyOption... options) throws IOException {
        Path s = unroot(source);
        Path t = unroot(target);
        if (log.isTraceEnabled()) {
            log.trace("copy({})[{}]: {}[{}]", source, s, target, t);
        }
        FileSystemProvider p = provider(s);
        p.copy(s, t, options);
    }

    @Override
    public void move(Path source, Path target, CopyOption... options) throws IOException {
        Path s = unroot(source);
        Path t = unroot(target);
        if (log.isTraceEnabled()) {
            log.trace("move({})[{}]: {}[{}]", source, s, target, t);
        }
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
        RootedFileSystem fileSystem = getFileSystem(path);
        Path root = fileSystem.getRoot();
        return Files.getFileStore(root);
    }

    protected RootedFileSystem getFileSystem(Path path) throws FileSystemNotFoundException {
        Path real = unroot(path);
        Path rootInstance = null;
        RootedFileSystem fsInstance = null;
        synchronized (fileSystems) {
            // Cannot use forEach because the referenced variable are not effectively final
            for (Map.Entry<Path, RootedFileSystem> fse : fileSystems.entrySet()) {
                Path root = fse.getKey();
                RootedFileSystem fs = fse.getValue();
                if (real.equals(root)) {
                    return fs; // we were lucky to have the root
                }

                if (!real.startsWith(root)) {
                    continue;
                }

                // if already have a candidate prefer the longer match since both are prefixes of the real path
                if ((rootInstance == null) || (rootInstance.getNameCount() < root.getNameCount())) {
                    rootInstance = root;
                    fsInstance = fs;
                }
            }
        }

        if (fsInstance == null) {
            throw new FileSystemNotFoundException(path.toString());
        }

        if (log.isTraceEnabled()) {
            log.trace("getFileSystem({}): {}", path, fsInstance);
        }

        return fsInstance;
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
    public <A extends BasicFileAttributes> A readAttributes(Path path, Class<A> type, LinkOption... options)
            throws IOException {
        Path r = unroot(path);
        if (log.isTraceEnabled()) {
            log.trace("readAttributes({})[{}] type={}", path, r, type.getSimpleName());
        }

        FileSystemProvider p = provider(r);
        return p.readAttributes(r, type, options);
    }

    @Override
    public Map<String, Object> readAttributes(Path path, String attributes, LinkOption... options) throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        Map<String, Object> attrs = p.readAttributes(r, attributes, options);
        if (log.isTraceEnabled()) {
            log.trace("readAttributes({})[{}] {}: {}", path, r, attributes, attrs);
        }
        return attrs;
    }

    @Override
    public void setAttribute(Path path, String attribute, Object value, LinkOption... options) throws IOException {
        Path r = unroot(path);
        if (log.isTraceEnabled()) {
            log.trace("setAttribute({})[{}] {}={}", path, r, attribute, value);
        }
        FileSystemProvider p = provider(r);
        p.setAttribute(r, attribute, value, options);
    }

    protected FileSystemProvider provider(Path path) {
        FileSystem fs = path.getFileSystem();
        return fs.provider();
    }

    protected Path root(RootedFileSystem rfs, Path nat) {
        if (nat.isAbsolute()) {
            Path root = rfs.getRoot();
            Path rel = root.relativize(nat);
            return rfs.getPath("/" + rel.toString());
        } else {
            return rfs.getPath(nat.toString());
        }
    }

    /**
     * @param  path                      The original (rooted) {@link Path}
     * @return                           The actual <U>absolute <B>local</B></U> {@link Path} represented by the rooted
     *                                   one
     * @see                              #resolveLocalPath(RootedPath)
     * @throws IllegalArgumentException  if {@code null} path argument
     * @throws ProviderMismatchException if not a {@link RootedPath}
     */
    protected Path unroot(Path path) {
        Objects.requireNonNull(path, "No path to unroot");
        if (!(path instanceof RootedPath)) {
            throw new ProviderMismatchException(
                    "unroot(" + path + ") is not a " + RootedPath.class.getSimpleName()
                                                + " but rather a " + path.getClass().getSimpleName());
        }

        return resolveLocalPath((RootedPath) path);
    }

    /**
     * @param  path                 The original {@link RootedPath} - never {@code null}
     * @return                      The actual <U>absolute <B>local</B></U> {@link Path} represented by the rooted one
     * @throws InvalidPathException If the resolved path is not a proper sub-path of the rooted file system
     */
    protected Path resolveLocalPath(RootedPath path) {
        RootedPath absPath = Objects.requireNonNull(path, "No rooted path to resolve").toAbsolutePath();
        RootedFileSystem rfs = absPath.getFileSystem();
        Path root = rfs.getRoot();
        FileSystem lfs = root.getFileSystem();

        String rSep = ValidateUtils.checkNotNullAndNotEmpty(rfs.getSeparator(), "No rooted file system separator");
        ValidateUtils.checkTrue(rSep.length() == 1, "Bad rooted file system separator: %s", rSep);
        char rootedSeparator = rSep.charAt(0);

        String lSep = ValidateUtils.checkNotNullAndNotEmpty(lfs.getSeparator(), "No local file system separator");
        ValidateUtils.checkTrue(lSep.length() == 1, "Bad local file system separator: %s", lSep);
        char localSeparator = lSep.charAt(0);

        String r = absPath.toString();
        String subPath = r.substring(1);
        if (rootedSeparator != localSeparator) {
            subPath = subPath.replace(rootedSeparator, localSeparator);
        }

        Path resolved = root.resolve(subPath);
        resolved = resolved.normalize();
        resolved = resolved.toAbsolutePath();
        if (log.isTraceEnabled()) {
            log.trace("resolveLocalPath({}): {}", absPath, resolved);
        }

        /*
         * This can happen for Windows since we represent its paths as /C:/some/path, so substring(1) yields
         * C:/some/path - which is resolved as an absolute path (which we don't want).
         */
        if (!resolved.startsWith(root)) {
            throw new InvalidPathException(r, "Not under root");
        }
        return resolved;
    }
}
