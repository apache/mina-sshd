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
package org.apache.sshd.common.util.io;

import java.io.Closeable;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.CopyOption;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class IoUtils {

    public static final OpenOption[] EMPTY_OPEN_OPTIONS = new OpenOption[0];
    public static final CopyOption[] EMPTY_COPY_OPTIONS = new CopyOption[0];
    public static final LinkOption[] EMPTY_LINK_OPTIONS = new LinkOption[0];

    public static final List<String> WINDOWS_EXECUTABLE_EXTENSIONS = Collections.unmodifiableList(Arrays.asList(".bat", ".exe", ".cmd"));

    /**
     * Size of preferred work buffer when reading / writing data to / from streams
     */
    public static final int DEFAULT_COPY_SIZE = 8192;

    /**
     * The local O/S line separator
     */
    public static final String EOL = System.getProperty("line.separator");
    private static final byte[] EOL_BYTES = EOL.getBytes(StandardCharsets.UTF_8);

    private static final LinkOption[] NO_FOLLOW_OPTIONS = new LinkOption[]{LinkOption.NOFOLLOW_LINKS};

    /**
     * Private Constructor
     */
    private IoUtils() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    /**
     * @return The local platform line separator bytes as UTF-8. <B>Note:</B>
     * each call returns a <U>new</U> instance in order to avoid inadvertent
     * changes in shared objects
     * @see #EOL
     */
    public static byte[] getEOLBytes() {
        return EOL_BYTES.clone();
    }

    public static LinkOption[] getLinkOptions(boolean followLinks) {
        if (followLinks) {
            return EMPTY_LINK_OPTIONS;
        } else {    // return a clone that modifications to the array will not affect others
            return NO_FOLLOW_OPTIONS.clone();
        }
    }

    public static long copy(InputStream source, OutputStream sink) throws IOException {
        return copy(source, sink, DEFAULT_COPY_SIZE);
    }

    public static long copy(InputStream source, OutputStream sink, int bufferSize) throws IOException {
        long nread = 0L;
        byte[] buf = new byte[bufferSize];
        int n;
        while ((n = source.read(buf)) > 0) {
            sink.write(buf, 0, n);
            nread += n;
        }
        return nread;
    }

    /**
     * Closes a bunch of resources suppressing any {@link IOException}s their
     * {@link Closeable#close()} method may have thrown
     *
     * @param closeables The {@link Closeable}s to close
     * @return The <U>first</U> {@link IOException} that occurred during closing
     * of a resource - if more than one exception occurred, they are added as
     * suppressed exceptions to the first one
     * @see Throwable#getSuppressed()
     */
    public static IOException closeQuietly(Closeable... closeables) {
        IOException err = null;
        for (Closeable c : closeables) {
            try {
                if (c != null) {
                    c.close();
                }
            } catch (IOException e) {
                GenericUtils.accumulateException(err, e);
            }
        }

        return err;
    }

    /**
     * @param fileName The file name to be evaluated - ignored if {@code null}/empty
     * @return {@code true} if the file ends in one of the {@link #WINDOWS_EXECUTABLE_EXTENSIONS}
     */
    public static boolean isWindowsExecutable(String fileName) {
        if ((fileName == null) || (fileName.length() <= 0)) {
            return false;
        }
        for (String suffix : WINDOWS_EXECUTABLE_EXTENSIONS) {
            if (fileName.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }

    /**
     * If the &quot;posix&quot; view is supported, then it returns
     * {@link Files#getPosixFilePermissions(Path, LinkOption...)}, otherwise
     * uses the {@link #getPermissionsFromFile(File)} method
     *
     * @param path    The {@link Path}
     * @param options The {@link LinkOption}s to use when querying the permissions
     * @return A {@link Set} of {@link PosixFilePermission}
     * @throws IOException If failed to access the file system in order to
     *                     retrieve the permissions
     */
    public static Set<PosixFilePermission> getPermissions(Path path, LinkOption... options) throws IOException {
        FileSystem fs = path.getFileSystem();
        Collection<String> views = fs.supportedFileAttributeViews();
        if (views.contains("posix")) {
            return Files.getPosixFilePermissions(path, options);
        } else {
            return getPermissionsFromFile(path.toFile());
        }
    }

    /**
     * @param f The {@link File} to be checked
     * @return A {@link Set} of {@link PosixFilePermission}s based on whether
     * the file is readable/writable/executable. If so, then <U>all</U> the
     * relevant permissions are set (i.e., owner, group and others)
     */
    public static Set<PosixFilePermission> getPermissionsFromFile(File f) {
        Set<PosixFilePermission> perms = EnumSet.noneOf(PosixFilePermission.class);
        if (f.canRead()) {
            perms.add(PosixFilePermission.OWNER_READ);
            perms.add(PosixFilePermission.GROUP_READ);
            perms.add(PosixFilePermission.OTHERS_READ);
        }

        if (f.canWrite()) {
            perms.add(PosixFilePermission.OWNER_WRITE);
            perms.add(PosixFilePermission.GROUP_WRITE);
            perms.add(PosixFilePermission.OTHERS_WRITE);
        }

        if (isExecutable(f)) {
            perms.add(PosixFilePermission.OWNER_EXECUTE);
            perms.add(PosixFilePermission.GROUP_EXECUTE);
            perms.add(PosixFilePermission.OTHERS_EXECUTE);
        }

        return perms;
    }

    public static boolean isExecutable(File f) {
        if (f == null) {
            return false;
        }

        if (OsUtils.isWin32()) {
            return isWindowsExecutable(f.getName());
        } else {
            return f.canExecute();
        }
    }

    /**
     * If the &quot;posix&quot; view is supported, then it invokes
     * {@link Files#setPosixFilePermissions(Path, Set)}, otherwise
     * uses the {@link #setPermissionsToFile(File, Collection)} method
     *
     * @param path  The {@link Path}
     * @param perms The {@link Set} of {@link PosixFilePermission}s
     * @throws IOException If failed to access the file system
     */
    public static void setPermissions(Path path, Set<PosixFilePermission> perms) throws IOException {
        FileSystem fs = path.getFileSystem();
        Collection<String> views = fs.supportedFileAttributeViews();
        if (views.contains("posix")) {
            Files.setPosixFilePermissions(path, perms);
        } else {
            setPermissionsToFile(path.toFile(), perms);
        }
    }

    /**
     * @param f     The {@link File}
     * @param perms A {@link Collection} of {@link PosixFilePermission}s to set on it.
     *              <B>Note:</B> the file is set to readable/writable/executable not only by the
     *              owner if <U>any</U> of relevant the owner/group/others permission is set
     */
    public static void setPermissionsToFile(File f, Collection<PosixFilePermission> perms) {
        boolean readable = perms != null
                && (perms.contains(PosixFilePermission.OWNER_READ)
                        || perms.contains(PosixFilePermission.GROUP_READ)
                        || perms.contains(PosixFilePermission.OTHERS_READ));
        f.setReadable(readable, false);

        boolean writable = perms != null
                && (perms.contains(PosixFilePermission.OWNER_WRITE)
                        || perms.contains(PosixFilePermission.GROUP_WRITE)
                        || perms.contains(PosixFilePermission.OTHERS_WRITE));
        f.setWritable(writable, false);

        boolean executable = perms != null
                && (perms.contains(PosixFilePermission.OWNER_EXECUTE)
                        || perms.contains(PosixFilePermission.GROUP_EXECUTE)
                        || perms.contains(PosixFilePermission.OTHERS_EXECUTE));
        f.setExecutable(executable, false);
    }

    /**
     * <P>Get file owner.</P>
     *
     * @param path  The {@link Path}
     * @param options The {@link LinkOption}s to use when querying the owner
     * @return Owner of the file or null if unsupported. <B>Note:</B> for
     * <I>Windows</I> it strips any prepended domain or group name
     * @throws IOException If failed to access the file system
     * @see Files#getOwner(Path, LinkOption...)
     */
    public static String getFileOwner(Path path, LinkOption... options) throws IOException {
        try {
            UserPrincipal principal = Files.getOwner(path, options);
            String owner = (principal == null) ? null : principal.getName();
            return OsUtils.getCanonicalUser(owner);
        } catch (UnsupportedOperationException e) {
            return null;
        }
    }

    /**
     * <P>Checks if a file exists - <B>Note:</B> according to the
     * <A HREF="http://docs.oracle.com/javase/tutorial/essential/io/check.html">Java tutorial - Checking a File or Directory</A>:
     * </P>
     *
     * <PRE>
     * The methods in the Path class are syntactic, meaning that they operate
     * on the Path instance. But eventually you must access the file system
     * to verify that a particular Path exists, or does not exist. You can do
     * so with the exists(Path, LinkOption...) and the notExists(Path, LinkOption...)
     * methods. Note that !Files.exists(path) is not equivalent to Files.notExists(path).
     * When you are testing a file's existence, three results are possible:
     *
     * - The file is verified to exist.
     * - The file is verified to not exist.
     * - The file's status is unknown.
     *
     * This result can occur when the program does not have access to the file.
     * If both exists and notExists return false, the existence of the file cannot
     * be verified.
     * </PRE>
     *
     * @param path    The {@link Path} to be tested
     * @param options The {@link LinkOption}s to use
     * @return {@link Boolean#TRUE}/{@link Boolean#FALSE} or {@code null}
     * according to the file status as explained above
     */
    public static Boolean checkFileExists(Path path, LinkOption... options) {
        if (Files.exists(path, options)) {
            return Boolean.TRUE;
        } else if (Files.notExists(path, options)) {
            return Boolean.FALSE;
        } else {
            return null;
        }
    }

    /**
     * Read the requested number of bytes or fail if there are not enough left.
     *
     * @param input  where to read input from
     * @param buffer destination
     * @throws IOException  if there is a problem reading the file
     * @throws EOFException if the number of bytes read was incorrect
     */
    public static void readFully(InputStream input, byte[] buffer) throws IOException {
        readFully(input, buffer, 0, buffer.length);
    }

    /**
     * Read the requested number of bytes or fail if there are not enough left.
     *
     * @param input  where to read input from
     * @param buffer destination
     * @param offset initial offset into buffer
     * @param length length to read, must be &ge; 0
     * @throws IOException  if there is a problem reading the file
     * @throws EOFException if the number of bytes read was incorrect
     */
    public static void readFully(InputStream input, byte[] buffer, int offset, int length) throws IOException {
        int actual = read(input, buffer, offset, length);
        if (actual != length) {
            throw new EOFException("Premature EOF - expected=" + length + ", actual=" + actual);
        }
    }

    /**
     * Read as many bytes as possible until EOF or achieved required length
     *
     * @param input  where to read input from
     * @param buffer destination
     * @return actual length read; may be less than requested if EOF was reached
     * @throws IOException if a read error occurs
     */
    public static int read(InputStream input, byte[] buffer) throws IOException {
        return read(input, buffer, 0, buffer.length);
    }

    /**
     * Read as many bytes as possible until EOF or achieved required length
     *
     * @param input  where to read input from
     * @param buffer destination
     * @param offset initial offset into buffer
     * @param length length to read - ignored if non-positive
     * @return actual length read; may be less than requested if EOF was reached
     * @throws IOException if a read error occurs
     */
    public static int read(InputStream input, byte[] buffer, int offset, int length) throws IOException {
        for (int remaining = length, curOffset = offset; remaining > 0;) {
            int count = input.read(buffer, curOffset, remaining);
            if (count == -1) { // EOF before achieved required length
                return curOffset - offset;
            }

            remaining -= count;
            curOffset += count;
        }

        return length;
    }

    /**
     * @param perms    The current {@link PosixFilePermission}s - ignored if {@code null}/empty
     * @param excluded The permissions <U>not</U> allowed to exist - ignored if {@code null}/empty
     * @return The violating {@link PosixFilePermission} - {@code null}
     * if no violating permission found
     */
    public static PosixFilePermission validateExcludedPermissions(Collection<PosixFilePermission> perms, Collection<PosixFilePermission> excluded) {
        if (GenericUtils.isEmpty(perms) || GenericUtils.isEmpty(excluded)) {
            return null;
        }

        for (PosixFilePermission p : excluded) {
            if (perms.contains(p)) {
                return p;
            }
        }

        return null;
    }

    /**
     * @param path    The {@link Path} to check
     * @param options The {@link LinkOption}s to use when checking if path is a directory
     * @return The same input path if it is a directory
     * @throws UnsupportedOperationException if input path not a directory
     */
    public static Path ensureDirectory(Path path, LinkOption... options) {
        if (!Files.isDirectory(path, options)) {
            throw new UnsupportedOperationException("Not a directory: " + path);
        }
        return path;
    }

    /**
     * @param options The {@link LinkOption}s - OK if {@code null}/empty
     * @return {@code true} if the link options are {@code null}/empty or do
     * not contain {@link LinkOption#NOFOLLOW_LINKS}, {@code false} otherwise
     * (i.e., the array is not empty and contains the special value)
     */
    public static boolean followLinks(LinkOption... options) {
        if (GenericUtils.isEmpty(options)) {
            return true;
        }

        for (LinkOption localLinkOption : options) {
            if (localLinkOption == LinkOption.NOFOLLOW_LINKS) {
                return false;
            }
        }
        return true;
    }

    public static String appendPathComponent(String prefix, String component) {
        if (GenericUtils.isEmpty(prefix)) {
            return component;
        }

        if (GenericUtils.isEmpty(component)) {
            return prefix;
        }

        StringBuilder sb = new StringBuilder(prefix.length() + component.length() + File.separator.length()).append(prefix);

        if (sb.charAt(prefix.length() - 1) == File.separatorChar) {
            if (component.charAt(0) == File.separatorChar) {
                sb.append(component.substring(1));
            } else {
                sb.append(component);
            }
        } else {
            if (component.charAt(0) != File.separatorChar) {
                sb.append(File.separatorChar);
            }
            sb.append(component);
        }

        return sb.toString();
    }
}
