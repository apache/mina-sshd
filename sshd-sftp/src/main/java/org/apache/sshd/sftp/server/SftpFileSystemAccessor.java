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

package org.apache.sshd.sftp.server;

import java.io.IOException;
import java.io.StreamCorruptedException;
import java.nio.channels.Channel;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Set;

import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils.NavigableMapBuilder;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.SelectorUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.io.FileInfoExtractor;
import org.apache.sshd.common.util.io.IoUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SftpFileSystemAccessor {
    List<String> DEFAULT_UNIX_VIEW = Collections.singletonList("unix:*");

    /**
     * A case <U>insensitive</U> {@link NavigableMap} of {@link FileInfoExtractor}s to be used to complete attributes
     * that are deemed important enough to warrant an extra effort if not accessible via the file system attributes
     * views
     */
    NavigableMap<String, FileInfoExtractor<?>> FILEATTRS_RESOLVERS
            = NavigableMapBuilder.<String, FileInfoExtractor<?>> builder(String.CASE_INSENSITIVE_ORDER)
                    .put(IoUtils.REGFILE_VIEW_ATTR, FileInfoExtractor.ISREG)
                    .put(IoUtils.DIRECTORY_VIEW_ATTR, FileInfoExtractor.ISDIR)
                    .put(IoUtils.SYMLINK_VIEW_ATTR, FileInfoExtractor.ISSYMLINK)
                    .put(IoUtils.PERMISSIONS_VIEW_ATTR, FileInfoExtractor.PERMISSIONS)
                    .put(IoUtils.SIZE_VIEW_ATTR, FileInfoExtractor.SIZE)
                    .put(IoUtils.LASTMOD_TIME_VIEW_ATTR, FileInfoExtractor.LASTMODIFIED)
                    .immutable();

    /** Whether to invoke {@link FileChannel#force(boolean)} on files open for write when closing */
    String PROP_AUTO_SYNC_FILE_ON_CLOSE = "sftp-auto-fsync-on-close";

    /** Default value for {@value #PROP_AUTO_SYNC_FILE_ON_CLOSE} if none set */
    boolean DEFAULT_AUTO_SYNC_FILE_ON_CLOSE = true;

    SftpFileSystemAccessor DEFAULT = new SftpFileSystemAccessor() {
        @Override
        public String toString() {
            return SftpFileSystemAccessor.class.getSimpleName() + "[DEFAULT]";
        }
    };

    /**
     * Invoked in order to resolve remote file paths reference by the client into ones accessible by the server
     *
     * @param  subsystem            The SFTP subsystem instance that manages the session
     * @param  rootDir              The default root directory used to resolve relative paths - a.k.a. the
     *                              {@code chroot} location
     * @param  remotePath           The remote path - separated by '/'
     * @return                      The local {@link Path}
     * @throws IOException          If failed to resolve the local path
     * @throws InvalidPathException If bad local path specification
     * @see                         SftpSubsystemEnvironment#getDefaultDirectory()
     *                              SftpSubsystemEnvironment#getDefaultDirectory()
     */
    default Path resolveLocalFilePath(
            SftpSubsystemProxy subsystem, Path rootDir, String remotePath)
            throws IOException, InvalidPathException {
        String path = SelectorUtils.translateToLocalFileSystemPath(
                remotePath, '/', rootDir.getFileSystem());
        return rootDir.resolve(path);
    }

    /**
     * Invoked in order to determine the symbolic link follow options
     *
     * @param  subsystem   The SFTP subsystem instance that manages the session
     * @param  file        The referenced file
     * @param  cmd         The SFTP command that triggered this access
     * @param  extension   The SFTP extension that triggered this access - non-empty only for {SSH_FXP_EXTENDED} command
     * @param  followLinks Whether to follow symbolic links
     * @return             The {@link LinkOption}-s to use - invokes {@link IoUtils#getLinkOptions(boolean)} by default
     * @throws IOException if failed to resolve the required options
     * @see                <A HREF="https://issues.apache.org/jira/browse/SSHD-1137">SSHD-1137</A>
     */
    default LinkOption[] resolveFileAccessLinkOptions(
            SftpSubsystemProxy subsystem, Path file, int cmd, String extension, boolean followLinks)
            throws IOException {
        return IoUtils.getLinkOptions(followLinks);
    }

    /**
     * Invoked in order to allow intervention to the reported file attributes - e.g., add custom/extended properties
     *
     * @param  subsystem   The SFTP subsystem instance that manages the session
     * @param  file        The referenced file
     * @param  flags       A mask of the original required attributes
     * @param  attrs       The default resolved attributes map
     * @param  options     The {@link LinkOption}-s that were used to access the file's attributes
     * @return             The updated attributes map
     * @throws IOException If failed to resolve the attributes
     * @see                <A HREF="https://issues.apache.org/jira/browse/SSHD-1226">SSHD-1226</A>
     */
    default NavigableMap<String, Object> resolveReportedFileAttributes(
            SftpSubsystemProxy subsystem, Path file, int flags,
            NavigableMap<String, Object> attrs, LinkOption... options)
            throws IOException {
        return attrs;
    }

    /**
     * Invoked in order to allow processing of custom file attributes
     *
     * @param  subsystem   The SFTP subsystem instance that manages the session
     * @param  file        The referenced file
     * @param  extensions  The received extensions - may be {@code null}/empty
     * @param  options     The {@link LinkOption}-s that were used to access the file's standard attributes
     * @throws IOException If failed to apply the attributes
     */
    default void applyExtensionFileAttributes(
            SftpSubsystemProxy subsystem, Path file, Map<String, byte[]> extensions, LinkOption... options)
            throws IOException {
        // ignored
    }

    /**
     * Invoked in order to encode the outgoing referenced file name/path
     *
     * @param  subsystem   The SFTP subsystem instance that manages the session
     * @param  path        The associated file {@link Path} - <B>Note:</B> might be a symbolic link container
     * @param  buf         The target {@link Buffer} for the encoded string
     * @param  name        The string to send
     * @param  shortName   If {@code true} then this is the &quot;pure&quot; file name/path, otherwise it also contains
     *                     user/group/size/last-modified-time/etc.
     * @throws IOException If failed to resolve the remote name
     * @see                <A HREF="https://issues.apache.org/jira/browse/SSHD-1132">SSHD-1132</A>
     */
    default void putRemoteFileName(
            SftpSubsystemProxy subsystem, Path path, Buffer buf, String name, boolean shortName)
            throws IOException {
        buf.putString(name);
    }

    /**
     * Called whenever a new file is opened
     *
     * @param  subsystem   The SFTP subsystem instance that manages the session
     * @param  fileHandle  The {@link FileHandle} representing the created channel - may be {@code null} if not invoked
     *                     within the context of such a handle (special cases)
     * @param  file        The requested <U>local</U> file {@link Path} - same one returned by
     *                     {@link #resolveLocalFilePath(SftpSubsystemProxy, Path, String) resolveLocalFilePath}
     * @param  handle      The assigned file handle through which the remote peer references this file. May be
     *                     {@code null}/empty if the request is due to some internal functionality instead of due to
     *                     peer requesting a handle to a file.
     * @param  options     The requested {@link OpenOption}s
     * @param  attrs       The requested {@link FileAttribute}s
     * @return             The opened {@link SeekableByteChannel}
     * @throws IOException If failed to open
     */
    default SeekableByteChannel openFile(
            SftpSubsystemProxy subsystem, FileHandle fileHandle, Path file,
            String handle, Set<? extends OpenOption> options, FileAttribute<?>... attrs)
            throws IOException {
        /*
         * According to https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#page-33
         *
         * The 'attrs' field is ignored if an existing file is opened.
         */
        if (Files.exists(file)) {
            attrs = IoUtils.EMPTY_FILE_ATTRIBUTES;
        }

        return FileChannel.open(file, options, attrs);
    }

    /**
     * Called when locking a section of a file is requested
     *
     * @param  subsystem   The SFTP subsystem instance that manages the session
     * @param  fileHandle  The {@link FileHandle} representing the created channel
     * @param  file        The requested <U>local</U> file {@link Path} - same one returned by
     *                     {@link #resolveLocalFilePath(SftpSubsystemProxy, Path, String) resolveLocalFilePath}
     * @param  handle      The assigned file handle through which the remote peer references this file
     * @param  channel     The original {@link Channel} that was returned by
     *                     {@link #openFile(SftpSubsystemProxy, FileHandle, Path, String, Set, FileAttribute...)}
     * @param  position    The position at which the locked region is to start - must be non-negative
     * @param  size        The size of the locked region; must be non-negative, and the sum
     *                     <tt>position</tt>&nbsp;+&nbsp;<tt>size</tt> must be non-negative
     * @param  shared      {@code true} to request a shared lock, {@code false} to request an exclusive lock
     * @return             A lock object representing the newly-acquired lock, or {@code null} if the lock could not be
     *                     acquired because another program holds an overlapping lock
     * @throws IOException If failed to honor the request
     * @see                FileChannel#tryLock(long, long, boolean)
     */
    @SuppressWarnings("checkstyle:ParameterNumber")
    default FileLock tryLock(
            SftpSubsystemProxy subsystem, FileHandle fileHandle, Path file, String handle,
            Channel channel, long position, long size, boolean shared)
            throws IOException {
        if (!(channel instanceof FileChannel)) {
            throw new StreamCorruptedException("Non file channel to lock: " + channel);
        }

        return ((FileChannel) channel).lock(position, size, shared);
    }

    /**
     * Called when file meta-data re-synchronization is required
     *
     * @param  subsystem   The SFTP subsystem instance that manages the session
     * @param  fileHandle  The {@link FileHandle} representing the created channel
     * @param  file        The requested <U>local</U> file {@link Path} - same one returned by
     *                     {@link #resolveLocalFilePath(SftpSubsystemProxy, Path, String) resolveLocalFilePath}
     * @param  handle      The assigned file handle through which the remote peer references this file
     * @param  channel     The original {@link Channel} that was returned by
     *                     {@link #openFile(SftpSubsystemProxy, FileHandle, Path, String, Set, FileAttribute...)}
     * @throws IOException If failed to execute the request
     * @see                FileChannel#force(boolean)
     * @see                <A HREF="https://github.com/openssh/openssh-portable/blob/master/PROTOCOL">OpenSSH - section
     *                     10</A>
     */
    default void syncFileData(
            SftpSubsystemProxy subsystem, FileHandle fileHandle, Path file, String handle, Channel channel)
            throws IOException {
        if (!(channel instanceof FileChannel)) {
            throw new StreamCorruptedException("Non file channel to sync: " + channel);
        }

        ((FileChannel) channel).force(true);
    }

    /**
     * Called to inform the accessor that it should close the file
     *
     * @param  subsystem   The SFTP subsystem instance that manages the session
     * @param  fileHandle  The {@link FileHandle} representing the created channel - may be {@code null} if not invoked
     *                     within the context of such a handle (special cases)
     * @param  file        The requested <U>local</U> file {@link Path} - same one returned by
     *                     {@link #resolveLocalFilePath(SftpSubsystemProxy, Path, String) resolveLocalFilePath}
     * @param  handle      The assigned file handle through which the remote peer references this file
     * @param  channel     The original {@link Channel} that was returned by
     *                     {@link #openFile(SftpSubsystemProxy, FileHandle, Path, String, Set, FileAttribute...)}
     * @param  options     The original options used to open the channel
     * @throws IOException If failed to execute the request
     */
    default void closeFile(
            SftpSubsystemProxy subsystem, FileHandle fileHandle, Path file,
            String handle, Channel channel, Set<? extends OpenOption> options)
            throws IOException {
        if ((channel == null) || (!channel.isOpen())) {
            return;
        }

        if ((channel instanceof FileChannel)
                && GenericUtils.containsAny(options, IoUtils.WRITEABLE_OPEN_OPTIONS)
                && PropertyResolverUtils.getBooleanProperty(
                        subsystem.getSession(), PROP_AUTO_SYNC_FILE_ON_CLOSE, DEFAULT_AUTO_SYNC_FILE_ON_CLOSE)) {
            ((FileChannel) channel).force(true);
        }

        channel.close();
    }

    /**
     * Called when a new directory stream is requested
     *
     * @param  subsystem   The SFTP subsystem instance that manages the session
     * @param  dirHandle   The {@link DirectoryHandle} representing the stream
     * @param  dir         The requested <U>local</U> directory {@link Path} - same one returned by
     *                     {@link #resolveLocalFilePath(SftpSubsystemProxy, Path, String) resolveLocalFilePath}
     * @param  handle      The assigned directory handle through which the remote peer references this directory
     * @return             The opened {@link DirectoryStream}
     * @throws IOException If failed to open
     */
    default DirectoryStream<Path> openDirectory(
            SftpSubsystemProxy subsystem, DirectoryHandle dirHandle, Path dir, String handle)
            throws IOException {
        return Files.newDirectoryStream(dir);
    }

    /**
     * Called when a directory stream is no longer required
     *
     * @param  subsystem   The SFTP subsystem instance that manages the session
     * @param  dirHandle   The {@link DirectoryHandle} representing the stream - may be {@code null} if not invoked
     *                     within the context of such a handle (special cases)
     * @param  dir         The requested <U>local</U> directory {@link Path} - same one returned by
     *                     {@link #resolveLocalFilePath(SftpSubsystemProxy, Path, String) resolveLocalFilePath}
     * @param  handle      The assigned directory handle through which the remote peer references this directory
     * @param  ds          The disposed {@link DirectoryStream}
     * @throws IOException If failed to open
     */
    default void closeDirectory(
            SftpSubsystemProxy subsystem, DirectoryHandle dirHandle,
            Path dir, String handle, DirectoryStream<Path> ds)
            throws IOException {
        if (ds == null) {
            return; // debug breakpoint
        }

        ds.close();
    }

    /**
     * Invoked when required to retrieve file attributes for a specific file system view
     *
     * @param  subsystem   The SFTP subsystem instance that manages the session
     * @param  file        The requested <U>local</U> file {@link Path} - same one returned by
     *                     {@link #resolveLocalFilePath(SftpSubsystemProxy, Path, String) resolveLocalFilePath}
     * @param  view        The required view name
     * @param  options     The access {@link LinkOption}-s
     * @return             A {@link Map} of all the attributes available for the file in the view
     * @throws IOException If failed to read the attributes
     * @see                Files#readAttributes(Path, String, LinkOption...)
     */
    default Map<String, ?> readFileAttributes(
            SftpSubsystemProxy subsystem, Path file, String view, LinkOption... options)
            throws IOException {
        return Files.readAttributes(file, view, options);
    }

    /**
     * Sets a view attribute for a local file
     *
     * @param  subsystem   The SFTP subsystem instance that manages the session
     * @param  file        The requested <U>local</U> file {@link Path} - same one returned by
     *                     {@link #resolveLocalFilePath(SftpSubsystemProxy, Path, String) resolveLocalFilePath}
     * @param  view        The required view name
     * @param  attribute   The attribute name
     * @param  value       The attribute value
     * @param  options     The access {@link LinkOption}-s
     * @throws IOException If failed to set the attribute
     */
    default void setFileAttribute(
            SftpSubsystemProxy subsystem, Path file, String view,
            String attribute, Object value, LinkOption... options)
            throws IOException {
        if (value == null) {
            return;
        }

        Files.setAttribute(file, view + ":" + attribute, value, options);
    }

    default UserPrincipal resolveFileOwner(
            SftpSubsystemProxy subsystem, Path file, UserPrincipal name)
            throws IOException {
        FileSystem fileSystem = file.getFileSystem();
        UserPrincipalLookupService lookupService = fileSystem.getUserPrincipalLookupService();
        String username = name.toString();

        if (lookupService == null) {
            throw new UserPrincipalNotFoundException(username);
        }

        return lookupService.lookupPrincipalByName(username);
    }

    default void setFileOwner(
            SftpSubsystemProxy subsystem, Path file, Principal value, LinkOption... options)
            throws IOException {
        if (value == null) {
            return;
        }

        FileOwnerAttributeView view = Files.getFileAttributeView(file, FileOwnerAttributeView.class, options);
        if (view == null) {
            throw new UnsupportedOperationException("Owner view not supported for " + file);
        }

        if (!(value instanceof UserPrincipal)) {
            throw new StreamCorruptedException(
                    "Owner is not " + UserPrincipal.class.getSimpleName() + ": " + value.getClass().getSimpleName());
        }

        view.setOwner((UserPrincipal) value);
    }

    default GroupPrincipal resolveGroupOwner(
            SftpSubsystemProxy subsystem, Path file, GroupPrincipal name)
            throws IOException {
        FileSystem fileSystem = file.getFileSystem();
        UserPrincipalLookupService lookupService = fileSystem.getUserPrincipalLookupService();
        String groupName = name.toString();
        if (lookupService == null) {
            throw new UserPrincipalNotFoundException(groupName);
        }
        return lookupService.lookupPrincipalByGroupName(groupName);

    }

    default void setGroupOwner(
            SftpSubsystemProxy subsystem, Path file, Principal value, LinkOption... options)
            throws IOException {
        if (value == null) {
            return;
        }

        PosixFileAttributeView view = Files.getFileAttributeView(file, PosixFileAttributeView.class, options);
        if (view == null) {
            throw new UnsupportedOperationException("POSIX view not supported");
        }

        if (!(value instanceof GroupPrincipal)) {
            throw new StreamCorruptedException(
                    "Group is not " + GroupPrincipal.class.getSimpleName() + ": " + value.getClass().getSimpleName());
        }

        view.setGroup((GroupPrincipal) value);
    }

    default void setFilePermissions(
            SftpSubsystemProxy subsystem, Path file, Set<PosixFilePermission> perms, LinkOption... options)
            throws IOException {
        if (OsUtils.isWin32()) {
            IoUtils.setPermissionsToFile(file.toFile(), perms);
            return;
        }

        PosixFileAttributeView view = Files.getFileAttributeView(file, PosixFileAttributeView.class, options);
        if (view == null) {
            throw new UnsupportedOperationException("POSIX view not supported for " + file);
        }

        view.setPermissions(perms);
    }

    default void setFileAccessControl(
            SftpSubsystemProxy subsystem, Path file, List<AclEntry> acl, LinkOption... options)
            throws IOException {
        AclFileAttributeView view = Files.getFileAttributeView(file, AclFileAttributeView.class, options);
        if (view == null) {
            throw new UnsupportedOperationException("ACL view not supported for " + file);
        }

        view.setAcl(acl);
    }

    default void createDirectory(SftpSubsystemProxy subsystem, Path path) throws IOException {
        Files.createDirectory(path);
    }

    /**
     * Invoked in order to create a link to a path
     *
     * @param  subsystem   The SFTP subsystem instance that manages the session
     * @param  link        The requested <U>link</U> {@link Path} - same one returned by
     *                     {@link #resolveLocalFilePath(SftpSubsystemProxy, Path, String) resolveLocalFilePath}
     * @param  existing    The <U>existing</U> {@link Path} that the link should reference
     * @param  symLink     {@code true} if this should be a symbolic link
     * @throws IOException If failed to create the link
     * @see                Files#createLink(Path, Path)
     * @see                Files#createSymbolicLink(Path, Path, FileAttribute...)
     */
    default void createLink(
            SftpSubsystemProxy subsystem, Path link, Path existing, boolean symLink)
            throws IOException {
        if (symLink) {
            Files.createSymbolicLink(link, existing);
        } else {
            Files.createLink(link, existing);
        }
    }

    default String resolveLinkTarget(SftpSubsystemProxy subsystem, Path link) throws IOException {
        Path target = Files.readSymbolicLink(link);
        return target.toString();
    }

    default void renameFile(
            SftpSubsystemProxy subsystem, Path oldPath, Path newPath, Collection<CopyOption> opts)
            throws IOException {
        Files.move(oldPath, newPath,
                GenericUtils.isEmpty(opts)
                        ? IoUtils.EMPTY_COPY_OPTIONS
                        : opts.toArray(new CopyOption[opts.size()]));
    }

    default void copyFile(
            SftpSubsystemProxy subsystem, Path src, Path dst, Collection<CopyOption> opts)
            throws IOException {
        Files.copy(src, dst,
                GenericUtils.isEmpty(opts)
                        ? IoUtils.EMPTY_COPY_OPTIONS
                        : opts.toArray(new CopyOption[opts.size()]));
    }

    default void removeFile(
            SftpSubsystemProxy subsystem, Path path, boolean isDirectory)
            throws IOException {
        Files.delete(path);
    }
}
