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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessDeniedException;
import java.nio.file.AccessMode;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.FileSystemLoopException;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.NotLinkException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.ProviderMismatchException;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.spi.FileSystemProvider;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutorService;

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
        try {
            return p.newInputStream(r, options);
        } catch (IOException ex) {
            throw translateIoException(ex, path);
        }
    }

    @Override
    public OutputStream newOutputStream(Path path, OpenOption... options) throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        try {
            return p.newOutputStream(r, options);
        } catch (IOException ex) {
            throw translateIoException(ex, path);
        }
    }

    @Override
    public FileChannel newFileChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs)
            throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        try {
            return p.newFileChannel(r, options, attrs);
        } catch (IOException ex) {
            throw translateIoException(ex, path);
        }
    }

    @Override
    public AsynchronousFileChannel newAsynchronousFileChannel(
            Path path, Set<? extends OpenOption> options, ExecutorService executor, FileAttribute<?>... attrs)
            throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        try {
            return p.newAsynchronousFileChannel(r, options, executor, attrs);
        } catch (IOException ex) {
            throw translateIoException(ex, path);
        }
    }

    @Override
    public SeekableByteChannel newByteChannel(Path path, Set<? extends OpenOption> options, FileAttribute<?>... attrs)
            throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        try {
            return p.newByteChannel(r, options, attrs);
        } catch (IOException ex) {
            throw translateIoException(ex, path);
        }
    }

    @Override
    public DirectoryStream<Path> newDirectoryStream(Path dir, DirectoryStream.Filter<? super Path> filter) throws IOException {
        Path r = unroot(dir);
        FileSystemProvider p = provider(r);
        try {
            return root(((RootedPath) dir).getFileSystem(), p.newDirectoryStream(r, filter));
        } catch (IOException ex) {
            throw translateIoException(ex, dir);
        }
    }

    protected DirectoryStream<Path> root(RootedFileSystem rfs, DirectoryStream<Path> ds) {
        if (ds instanceof SecureDirectoryStream) {
            return new RootedSecureDirectoryStream(rfs, (SecureDirectoryStream<Path>) ds);
        }
        return new RootedDirectoryStream(rfs, ds);
    }

    @Override
    public void createDirectory(Path dir, FileAttribute<?>... attrs) throws IOException {
        Path r = unroot(dir);
        FileSystemProvider p = provider(r);
        try {
            p.createDirectory(r, attrs);
        } catch (IOException ex) {
            throw translateIoException(ex, dir);
        }
    }

    @Override
    public void createSymbolicLink(Path link, Path target, FileAttribute<?>... attrs) throws IOException {
        // make sure symlink cannot break out of chroot jail. If it is unsafe, simply thrown an exception. This is
        // to ensure that symlink semantics are maintained when it is safe, and creation fails when not.
        RootedFileSystemUtils.validateSafeRelativeSymlink(target);
        Path l = unroot(link);
        Path t = target.isAbsolute() ? unroot(target) : l.getFileSystem().getPath(target.toString());

        FileSystemProvider p = provider(l);
        try {
            p.createSymbolicLink(l, t, attrs);

            if (log.isDebugEnabled()) {
                log.debug("createSymbolicLink({} => {}", l, t);
            }
        } catch (IOException ex) {
            throw translateIoException(ex, link);
        }
    }

    @Override
    public void createLink(Path link, Path existing) throws IOException {
        Path l = unroot(link);
        Path t = unroot(existing);

        try {
            provider(l).createLink(l, t);
            if (log.isDebugEnabled()) {
                log.debug("createLink({} => {}", l, t);
            }
        } catch (IOException ex) {
            throw translateIoException(ex, link);
        }
    }

    @Override
    public void delete(Path path) throws IOException {
        Path r = unroot(path);
        if (log.isTraceEnabled()) {
            log.trace("delete({}): {}", path, r);
        }
        FileSystemProvider p = provider(r);
        try {
            p.delete(r);
        } catch (IOException ex) {
            throw translateIoException(ex, path);
        }
    }

    @Override
    public boolean deleteIfExists(Path path) throws IOException {
        Path r = unroot(path);
        if (log.isTraceEnabled()) {
            log.trace("deleteIfExists({}): {}", path, r);
        }
        FileSystemProvider p = provider(r);
        try {
            return p.deleteIfExists(r);
        } catch (IOException ex) {
            throw translateIoException(ex, path);
        }
    }

    @Override
    public Path readSymbolicLink(Path link) throws IOException {
        Path r = unroot(link);
        FileSystemProvider p = provider(r);
        try {
            Path t = p.readSymbolicLink(r);
            Path target = root((RootedFileSystem) link.getFileSystem(), t);
            if (log.isTraceEnabled()) {
                log.trace("readSymbolicLink({})[{}]: {}[{}]", link, r, target, t);
            }
            return target;
        } catch (IOException ex) {
            throw translateIoException(ex, link);
        }
    }

    @Override
    public void copy(Path source, Path target, CopyOption... options) throws IOException {
        Path s = unroot(source);
        Path t = unroot(target);
        if (log.isTraceEnabled()) {
            log.trace("copy({})[{}]: {}[{}]", source, s, target, t);
        }
        FileSystemProvider p = provider(s);
        try {
            p.copy(s, t, options);
        } catch (IOException ex) {
            throw translateIoException(ex, source);
        }
    }

    @Override
    public void move(Path source, Path target, CopyOption... options) throws IOException {
        Path s = unroot(source);
        Path t = unroot(target);
        if (log.isTraceEnabled()) {
            log.trace("move({})[{}]: {}[{}]", source, s, target, t);
        }
        FileSystemProvider p = provider(s);
        try {
            p.move(s, t, options);
        } catch (IOException ex) {
            throw translateIoException(ex, source);
        }
    }

    @Override
    public boolean isSameFile(Path path, Path path2) throws IOException {
        Path r = unroot(path);
        Path r2 = unroot(path2);
        FileSystemProvider p = provider(r);
        try {
            return p.isSameFile(r, r2);
        } catch (IOException ex) {
            throw translateIoException(ex, path);
        }
    }

    @Override
    public boolean isHidden(Path path) throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        try {
            return p.isHidden(r);
        } catch (IOException ex) {
            throw translateIoException(ex, path);
        }
    }

    @Override
    public FileStore getFileStore(Path path) throws IOException {
        RootedFileSystem fileSystem = getFileSystem(path);
        Path root = fileSystem.getRoot();
        try {
            return Files.getFileStore(root);
        } catch (IOException ex) {
            throw translateIoException(ex, path);
        }
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
        try {
            p.checkAccess(r, modes);
        } catch (IOException ex) {
            throw translateIoException(ex, path);
        }
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
        try {
            return p.readAttributes(r, type, options);
        } catch (IOException ex) {
            throw translateIoException(ex, path);
        }
    }

    @Override
    public Map<String, Object> readAttributes(Path path, String attributes, LinkOption... options) throws IOException {
        Path r = unroot(path);
        FileSystemProvider p = provider(r);
        try {
            Map<String, Object> attrs = p.readAttributes(r, attributes, options);
            if (log.isTraceEnabled()) {
                log.trace("readAttributes({})[{}] {}: {}", path, r, attributes, attrs);
            }
            return attrs;
        } catch (IOException ex) {
            throw translateIoException(ex, path);
        }
    }

    @Override
    public void setAttribute(Path path, String attribute, Object value, LinkOption... options) throws IOException {
        Path r = unroot(path);
        if (log.isTraceEnabled()) {
            log.trace("setAttribute({})[{}] {}={}", path, r, attribute, value);
        }
        FileSystemProvider p = provider(r);
        try {
            p.setAttribute(r, attribute, value, options);
        } catch (IOException ex) {
            throw translateIoException(ex, path);
        }
    }

    protected FileSystemProvider provider(Path path) {
        FileSystem fs = path.getFileSystem();
        return fs.provider();
    }

    protected Path root(RootedFileSystem rfs, Path nat) {
        if (nat.isAbsolute()) {
            // preferred case - this isn't a symlink out of our jail
            if (nat.startsWith(rfs.getRoot())) {
                // If we have the same number of parts as the root, and start with the root, we must be the root.
                if (nat.getNameCount() == rfs.getRoot().getNameCount()) {
                    return rfs.getPath("/");
                }

                // We are the root, and more. Get the first name past the root because of how getPath works
                String firstName = "/" + nat.getName(rfs.getRoot().getNameCount());

                // the rooted path should have the number of parts past the root
                String[] varargs = new String[nat.getNameCount() - rfs.getRoot().getNameCount() - 1];
                int varargsCounter = 0;
                for (int i = 1 + rfs.getRoot().getNameCount(); i < nat.getNameCount(); i++) {
                    varargs[varargsCounter++] = nat.getName(i).toString();
                }
                return rfs.getPath(firstName, varargs);
            }

            // This is the case where there's a symlink jailbreak, so we return a relative link as the directories above
            // the chroot don't make sense to present
            // The behavior with the fs class is that we follow the symlink. Note that this is dangerous.
            Path root = rfs.getRoot();
            Path rel = root.relativize(nat);
            return rfs.getPath("/" + rel);
        } else {
            // For a relative symlink, simply return it as a RootedPath. Note that this may break out of the chroot.
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
            throw new ProviderMismatchException("unroot(" + path + ") is not a " + RootedPath.class.getSimpleName()
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
        Objects.requireNonNull(path, "No rooted path to resolve");
        RootedFileSystem rfs = path.getFileSystem();
        Path root = rfs.getRoot();
        // initialize a list for the new file name parts
        Path resolved = IoUtils.chroot(root, path);

        /*
         * This can happen for Windows since we represent its paths as /C:/some/path, so substring(1) yields
         * C:/some/path - which is resolved as an absolute path (which we don't want).
         *
         * This also is a security assertion to protect against unknown attempts to break out of the chroot jail
         */
        if (!resolved.normalize().startsWith(root)) {
            throw new InvalidPathException(root.toString(), "Not under root");
        }
        return resolved;
    }

    private IOException translateIoException(IOException ex, Path rootedPath) {
        // cast is safe as path was unrooted earlier.
        RootedPath rootedPathCasted = (RootedPath) rootedPath;
        Path root = rootedPathCasted.getFileSystem().getRoot();

        if (ex instanceof FileSystemException) {
            String file = fixExceptionFileName(root, rootedPath, ((FileSystemException) ex).getFile());
            String otherFile = fixExceptionFileName(root, rootedPath, ((FileSystemException) ex).getOtherFile());
            String reason = ((FileSystemException) ex).getReason();
            if (NoSuchFileException.class.equals(ex.getClass())) {
                return new NoSuchFileException(file, otherFile, reason);
            } else if (FileSystemLoopException.class.equals(ex.getClass())) {
                return new FileSystemLoopException(file);
            } else if (NotDirectoryException.class.equals(ex.getClass())) {
                return new NotDirectoryException(file);
            } else if (DirectoryNotEmptyException.class.equals(ex.getClass())) {
                return new DirectoryNotEmptyException(file);
            } else if (NotLinkException.class.equals(ex.getClass())) {
                return new NotLinkException(file);
            } else if (AtomicMoveNotSupportedException.class.equals(ex.getClass())) {
                return new AtomicMoveNotSupportedException(file, otherFile, reason);
            } else if (FileAlreadyExistsException.class.equals(ex.getClass())) {
                return new FileAlreadyExistsException(file, otherFile, reason);
            } else if (AccessDeniedException.class.equals(ex.getClass())) {
                return new AccessDeniedException(file, otherFile, reason);
            }
            return new FileSystemException(file, otherFile, reason);
        } else if (ex.getClass().equals(FileNotFoundException.class)) {
            return new FileNotFoundException(ex.getLocalizedMessage().replace(root.toString(), ""));
        }
        // not sure how to translate, so leave as is. Hopefully does not leak data
        return ex;
    }

    private String fixExceptionFileName(Path root, Path rootedPath, String fileName) {
        if (fileName == null) {
            return null;
        }

        Path toFix = root.getFileSystem().getPath(fileName);
        if (toFix.getNameCount() == root.getNameCount()) {
            // return the root
            return rootedPath.getFileSystem().getSeparator();
        }

        StringBuilder ret = new StringBuilder();
        for (int partNum = root.getNameCount(); partNum < toFix.getNameCount(); partNum++) {
            ret.append(rootedPath.getFileSystem().getSeparator());
            ret.append(toFix.getName(partNum++));
        }
        return ret.toString();
    }
}
