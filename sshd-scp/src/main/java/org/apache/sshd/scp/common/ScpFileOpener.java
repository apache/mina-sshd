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

package org.apache.sshd.scp.common;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.SshException;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.SelectorUtils;
import org.apache.sshd.common.util.io.DirectoryScanner;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.scp.common.helpers.ScpTimestampCommandDetails;

/**
 * Plug-in mechanism for users to intervene in the SCP process - e.g., apply some kind of traffic shaping mechanism,
 * display upload/download progress, etc...
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ScpFileOpener {

    /**
     * Invoked when receiving a new file to via a directory command
     *
     * @param  session     The client/server {@link Session} through which the transfer is being executed
     * @param  localPath   The target local path
     * @param  name        The target file name
     * @param  preserve    Whether requested to preserve the permissions and timestamp
     * @param  permissions The requested file permissions
     * @param  time        The requested {@link ScpTimestampCommandDetails} - may be {@code null} if nothing to update
     * @return             The actual target file path for the incoming file/directory
     * @throws IOException If failed to resolve the file path
     * @see                #updateFileProperties(Path, Set, ScpTimestampCommandDetails) updateFileProperties
     */
    default Path resolveIncomingFilePath(
            Session session, Path localPath, String name, boolean preserve, Set<PosixFilePermission> permissions,
            ScpTimestampCommandDetails time)
            throws IOException {
        LinkOption[] options = IoUtils.getLinkOptions(true);
        Boolean status = IoUtils.checkFileExists(localPath, options);
        if (status == null) {
            throw new AccessDeniedException("Receive directory existence status cannot be determined: " + localPath);
        }

        Path file = null;
        if (status && Files.isDirectory(localPath, options)) {
            String localName = name.replace('/', File.separatorChar);
            file = localPath.resolve(localName);
        } else if (!status) {
            Path parent = localPath.getParent();

            status = IoUtils.checkFileExists(parent, options);
            if (status == null) {
                throw new AccessDeniedException(
                        "Receive directory parent (" + parent + ") existence status cannot be determined for " + localPath);
            }

            if (status && Files.isDirectory(parent, options)) {
                file = localPath;
            }
        }

        if (file == null) {
            throw new IOException("Cannot write to " + localPath);
        }

        status = IoUtils.checkFileExists(file, options);
        if (status == null) {
            throw new AccessDeniedException("Receive directory file existence status cannot be determined: " + file);
        }

        if (!(status && Files.isDirectory(file, options))) {
            Files.createDirectory(file);
        }

        if (preserve) {
            updateFileProperties(file, permissions, time);
        }

        return file;
    }

    /**
     * Invoked when required to send a pattern of files
     *
     * @param  session     The client/server {@link Session} through which the transfer is being executed
     * @param  basedir     The base directory - may be {@code null}/empty to indicate CWD
     * @param  pattern     The required pattern - ignored if {@code null}/empty - returns empty result
     * @return             The matching <U>relative paths</U> of the children to send
     * @throws IOException If failed to scan the directory
     */
    default Iterable<Path> getMatchingFilesToSend(Session session, Path basedir, String pattern) throws IOException {
        if (GenericUtils.isEmpty(pattern)) {
            return Collections.emptyList();
        }

        if (basedir == null) {
            String cwdLocal = System.getProperty("user.dir");
            Path cwdPath = Paths.get(cwdLocal);
            basedir = cwdPath.toAbsolutePath();
        }

        // We may reach this location with a rooted path which uses '/' as the separator
        FileSystem fs = basedir.getFileSystem();
        String fsSep = fs.getSeparator();
        DirectoryScanner ds = new DirectoryScanner(basedir);
        ds.setSeparator(fsSep);
        ds.setIncludes(Collections.singletonList(pattern));

        return ds.scan();
    }

    /**
     * Invoked on a local path in order to decide whether it should be sent as a file or as a directory
     *
     * @param  session     The client/server {@link Session} through which the transfer is being executed
     * @param  path        The local {@link Path}
     * @param  options     The {@link LinkOption}-s
     * @return             Whether to send the file as a regular one - <B>Note:</B> if {@code false} then the
     *                     {@link #sendAsDirectory(Session, Path, LinkOption...)} is consulted.
     * @throws IOException If failed to decide
     */
    default boolean sendAsRegularFile(Session session, Path path, LinkOption... options)
            throws IOException {
        return Files.isRegularFile(path, options);
    }

    /**
     * Invoked on a local path in order to decide whether it should be sent as a file or as a directory
     *
     * @param  session     The client/server {@link Session} through which the transfer is being executed
     * @param  path        The local {@link Path}
     * @param  options     The {@link LinkOption}-s
     * @return             Whether to send the file as a directory - <B>Note:</B> if {@code true} then
     *                     {@link #getLocalFolderChildren(Session, Path)} is consulted
     * @throws IOException If failed to decide
     */
    default boolean sendAsDirectory(Session session, Path path, LinkOption... options)
            throws IOException {
        return Files.isDirectory(path, options);
    }

    /**
     * Invoked when required to send all children of a local directory
     *
     * @param  session     The client/server {@link Session} through which the transfer is being executed
     * @param  path        The local folder {@link Path}
     * @return             The {@link DirectoryStream} of children to send - <B>Note:</B> for each child the decision
     *                     whether to send it as a file or a directory will be reached by consulting the respective
     *                     {@link #sendAsRegularFile(Session, Path, LinkOption...) sendAsRegularFile} and
     *                     {@link #sendAsDirectory(Session, Path, LinkOption...) sendAsDirectory} methods
     * @throws IOException If failed to provide the children stream
     * @see                #sendAsDirectory(Session, Path, LinkOption...) sendAsDirectory
     */
    default DirectoryStream<Path> getLocalFolderChildren(Session session, Path path) throws IOException {
        return Files.newDirectoryStream(path);
    }

    default BasicFileAttributes getLocalBasicFileAttributes(
            Session session, Path path, LinkOption... options)
            throws IOException {
        BasicFileAttributeView view = Files.getFileAttributeView(path, BasicFileAttributeView.class, options);
        return view.readAttributes();
    }

    default Set<PosixFilePermission> getLocalFilePermissions(
            Session session, Path path, LinkOption... options)
            throws IOException {
        return IoUtils.getPermissions(path, options);
    }

    /**
     * @param  session              The client/server {@link Session} through which the transfer is being executed
     * @param  fileSystem           The <U>local</U> {@link FileSystem} on which local file should reside
     * @param  commandPath          The command path using the <U>local</U> file separator
     * @return                      The resolved absolute and normalized local {@link Path}
     * @throws IOException          If failed to resolve the path
     * @throws InvalidPathException If invalid local path value
     */
    default Path resolveLocalPath(Session session, FileSystem fileSystem, String commandPath)
            throws IOException, InvalidPathException {
        String path = SelectorUtils.translateToLocalFileSystemPath(commandPath, File.separatorChar, fileSystem);
        Path lcl = fileSystem.getPath(path);
        Path abs = lcl.isAbsolute() ? lcl : lcl.toAbsolutePath();
        return abs.normalize();
    }

    /**
     * Invoked when a request to receive something is processed
     *
     * @param  session     The client/server {@link Session} through which the transfer is being executed
     * @param  path        The local target {@link Path} of the request
     * @param  recursive   Whether the request is recursive
     * @param  shouldBeDir Whether target path is expected to be a directory
     * @param  preserve    Whether target path is expected to preserve attributes (permissions, times)
     * @return             The effective target path - default=same as input
     * @throws IOException If failed to resolve target location
     */
    default Path resolveIncomingReceiveLocation(
            Session session, Path path, boolean recursive, boolean shouldBeDir, boolean preserve)
            throws IOException {
        if (!shouldBeDir) {
            return path;
        }
        LinkOption[] options = IoUtils.getLinkOptions(true);
        Boolean status = IoUtils.checkFileExists(path, options);
        if (status == null) {
            throw new SshException("Target directory " + path + " is most like inaccessible");
        }
        if (!status) {
            throw new SshException("Target directory " + path + " does not exist");
        }
        if (!Files.isDirectory(path, options)) {
            throw new SshException("Target directory " + path + " is not a directory");
        }

        return path;
    }

    /**
     * Called when there is a candidate file/folder for sending
     *
     * @param  session     The client/server {@link Session} through which the transfer is being executed
     * @param  localPath   The original file/folder {@link Path} for sending
     * @param  options     The {@link LinkOption}-s to use for validation
     * @return             The effective outgoing file path (default=same as input)
     * @throws IOException If failed to resolve
     */
    default Path resolveOutgoingFilePath(
            Session session, Path localPath, LinkOption... options)
            throws IOException {
        Boolean status = IoUtils.checkFileExists(localPath, options);
        if (status == null) {
            throw new AccessDeniedException("Send file existence status cannot be determined: " + localPath);
        }
        if (!status) {
            throw new IOException(localPath + ": no such file or directory");
        }

        return localPath;
    }

    /**
     * Create an input stream to read from a file
     *
     * @param  session     The {@link Session} requesting the access
     * @param  file        The requested local file {@link Path}
     * @param  size        The expected transfer bytes count
     * @param  permissions The requested file permissions
     * @param  options     The {@link OpenOption}s - may be {@code null}/empty
     * @return             The open {@link InputStream} never {@code null}
     * @throws IOException If failed to open the file
     */
    InputStream openRead(
            Session session, Path file, long size, Set<PosixFilePermission> permissions, OpenOption... options)
            throws IOException;

    /**
     * Called when the stream obtained from {@link #openRead(Session, Path, long, Set, OpenOption...) openRead} is no
     * longer required since data has been successfully copied.
     *
     * @param  session     The {@link Session} requesting the access
     * @param  file        The requested local file {@link Path}
     * @param  size        The expected transfer bytes count
     * @param  permissions The requested file permissions
     * @param  stream      The {@link InputStream} to close
     * @throws IOException If failed to close the stream - <B>Note:</B> stream will be closed regardless of whether this
     *                     method throws an exception or not.
     */
    default void closeRead(
            Session session, Path file, long size, Set<PosixFilePermission> permissions, InputStream stream)
            throws IOException {
        if (stream != null) {
            stream.close();
        }
    }

    ScpSourceStreamResolver createScpSourceStreamResolver(Session session, Path path) throws IOException;

    /**
     * Create an output stream to write to a file
     *
     * @param  session     The {@link Session} requesting the access
     * @param  file        The requested local file {@link Path}
     * @param  size        The expected transfer byte count
     * @param  permissions The requested file permissions
     * @param  options     The {@link OpenOption}s - may be {@code null}/empty
     * @return             The open {@link OutputStream} never {@code null}
     * @throws IOException If failed to open the file
     */
    OutputStream openWrite(
            Session session, Path file, long size, Set<PosixFilePermission> permissions, OpenOption... options)
            throws IOException;

    /**
     * Called when output stream obtained from {@link #openWrite(Session, Path, long, Set, OpenOption...) openWrite} is
     * no longer needed since data copying has been successfully completed.
     *
     * @param  session     The {@link Session} requesting the access
     * @param  file        The requested local file {@link Path}
     * @param  size        The expected transfer byte count
     * @param  permissions The requested file permissions
     * @param  os          The opened {@link OutputStream}
     * @throws IOException If failed to close the stream - <B>Note:</B> stream will be closed regardless of whether this
     *                     method throws an exception or not.
     */
    default void closeWrite(
            Session session, Path file, long size, Set<PosixFilePermission> permissions, OutputStream os)
            throws IOException {
        if (os != null) {
            os.close();
        }
    }

    ScpTargetStreamResolver createScpTargetStreamResolver(Session session, Path path) throws IOException;

    static void updateFileProperties(Path file, Set<PosixFilePermission> perms, ScpTimestampCommandDetails time)
            throws IOException {
        IoUtils.setPermissions(file, perms);

        if (time != null) {
            BasicFileAttributeView view = Files.getFileAttributeView(file, BasicFileAttributeView.class);
            FileTime lastModified = FileTime.from(time.getLastModifiedTime(), TimeUnit.MILLISECONDS);
            FileTime lastAccess = FileTime.from(time.getLastAccessTime(), TimeUnit.MILLISECONDS);
            view.setTimes(lastModified, lastAccess, null);
        }
    }
}
