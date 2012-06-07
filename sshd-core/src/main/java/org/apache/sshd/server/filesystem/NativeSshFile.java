/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.server.filesystem;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.StringTokenizer;

import org.apache.sshd.server.SshFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <strong>Internal class, do not use directly.</strong>
 * 
 * This class wraps native file object.
 *
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class NativeSshFile implements SshFile {

    private final Logger LOG = LoggerFactory.getLogger(NativeSshFile.class);

    // the file name with respect to the user root.
    // The path separator character will be '/' and
    // it will always begin with '/'.
    private String fileName;

    private File file;

    private String userName;

    /**
     * Constructor, internal do not use directly.
     */
    protected NativeSshFile(final String fileName, final File file,
            final String userName) {
        if (fileName == null) {
            throw new IllegalArgumentException("fileName can not be null");
        }
        if (file == null) {
            throw new IllegalArgumentException("file can not be null");
        }

        if (fileName.length() == 0) {
            throw new IllegalArgumentException("fileName can not be empty");
        } else if (fileName.charAt(0) != '/') {
            throw new IllegalArgumentException("fileName must be an absolute path");
        }

        this.fileName = fileName;
        this.file = file;
        this.userName = userName;
    }

    /**
     * Get full name.
     */
    public String getAbsolutePath() {

        // strip the last '/' if necessary
        String fullName = fileName;
        int filelen = fullName.length();
        if ((filelen != 1) && (fullName.charAt(filelen - 1) == '/')) {
            fullName = fullName.substring(0, filelen - 1);
        }

        return fullName;
    }

    /**
     * Get short name.
     */
    public String getName() {

        // root - the short name will be '/'
        if (fileName.equals("/")) {
            return "/";
        }

        // strip the last '/'
        String shortName = fileName;
        int filelen = fileName.length();
        if (shortName.charAt(filelen - 1) == '/') {
            shortName = shortName.substring(0, filelen - 1);
        }

        // return from the last '/'
        int slashIndex = shortName.lastIndexOf('/');
        if (slashIndex != -1) {
            shortName = shortName.substring(slashIndex + 1);
        }
        return shortName;
    }

    /**
     * Get owner name
     */
    public String getOwner() {
        return userName;
    }

    /**
     * Is it a directory?
     */
    public boolean isDirectory() {
        return file.isDirectory();
    }

    /**
     * Is it a file?
     */
    public boolean isFile() {
        return file.isFile();
    }

    /**
     * Does this file exists?
     */
    public boolean doesExist() {
        return file.exists();
    }

    /**
     * Get file size.
     */
    public long getSize() {
        return file.length();
    }

    /**
     * Get last modified time.
     */
    public long getLastModified() {
        return file.lastModified();
    }

    /**
     * {@inheritDoc}
     */
    public boolean setLastModified(long time) {
        return file.setLastModified(time);
    }

    /**
     * Check read permission.
     */
    public boolean isReadable() {
        return file.canRead();
    }

    /**
     * Check file write permission.
     */
    public boolean isWritable() {
        LOG.debug("Checking if file exists");
        if (file.exists()) {
            LOG.debug("Checking can write: " + file.canWrite());
            return file.canWrite();
        }

        LOG.debug("Authorized");
        return true;
    }

    /**
     * File.canExecute() method is only available on JDK 1.6
     */
    private static final Method CAN_EXECUTE_METHOD;
    static {
        Method method = null;
        try {
           method = File.class.getMethod("canExecute");
        } catch (Throwable t) {
        }
        CAN_EXECUTE_METHOD = method;
    }

    /**
     * Check file exec permission.
     */
    public boolean isExecutable() {
        if (CAN_EXECUTE_METHOD != null) {
            try {
                return (Boolean) CAN_EXECUTE_METHOD.invoke(file);
            } catch (Throwable t) {
            }
        }
        // Default directories to being executable
        // as on unix systems to allow listing their contents.
        return file.isDirectory();
    }

    /**
     * Has delete permission.
     */
    public boolean isRemovable() {

        // root cannot be deleted
        if ("/".equals(fileName)) {
            return false;
        }

        /* Added 12/08/2008: in the case that the permission is not explicitly denied for this file
         * we will check if the parent file has write permission as most systems consider that a file can
         * be deleted when their parent directory is writable.
        */
        String fullName = getAbsolutePath();

        // we check FTPServer's write permission for this file.
//        if (user.authorize(new WriteRequest(fullName)) == null) {
//            return false;
//        }

        // In order to maintain consistency, when possible we delete the last '/' character in the String
        int indexOfSlash = fullName.lastIndexOf('/');
        String parentFullName;
        if (indexOfSlash == 0) {
            parentFullName = "/";
        } else {
            parentFullName = fullName.substring(0, indexOfSlash);
        }

        // we check if the parent FileObject is writable.
        NativeSshFile parentObject = new NativeSshFile(parentFullName, file
                .getAbsoluteFile().getParentFile(), userName);
        return parentObject.isWritable();
    }

    public SshFile getParentFile() {
        int indexOfSlash = getAbsolutePath().lastIndexOf('/');
        String parentFullName;
        if (indexOfSlash == 0) {
            parentFullName = "/";
        } else {
            parentFullName = getAbsolutePath().substring(0, indexOfSlash);
        }

        // we check if the parent FileObject is writable.
        return new NativeSshFile(parentFullName, file
                .getAbsoluteFile().getParentFile(), userName);
    }

    /**
     * Delete file.
     */
    public boolean delete() {
        boolean retVal = false;
        if (isRemovable()) {
            retVal = file.delete();
        }
        return retVal;
    }

    /**
     * Create a new file
     */
    public boolean create() throws IOException {
        return file.createNewFile();
    }

    /**
     * Truncate file to length 0.
     */
    public void truncate() throws IOException{
        RandomAccessFile tempFile = new RandomAccessFile(file, "rw");
        try {
            tempFile.setLength(0);
        } finally {
            tempFile.close();
        }
    }

    /**
     * Move file object.
     */
    public boolean move(final SshFile dest) {
        boolean retVal = false;
        if (dest.isWritable() && isReadable()) {
            File destFile = ((NativeSshFile) dest).file;

            if (destFile.exists()) {
                // renameTo behaves differently on different platforms
                // this check verifies that if the destination already exists,
                // we fail
                retVal = false;
            } else {
                retVal = file.renameTo(destFile);
            }
        }
        return retVal;
    }

    /**
     * Create directory.
     */
    public boolean mkdir() {
        boolean retVal = false;
        if (isWritable()) {
            retVal = file.mkdir();
        }
        return retVal;
    }

    /**
     * List files. If not a directory or does not exist, null will be returned.
     */
    public List<SshFile> listSshFiles() {

        // is a directory
        if (!file.isDirectory()) {
            return null;
        }

        // directory - return all the files
        File[] files = file.listFiles();
        if (files == null) {
            return null;
        }

        // make sure the files are returned in order
        Arrays.sort(files, new Comparator<File>() {
            public int compare(File f1, File f2) {
                return f1.getName().compareTo(f2.getName());
            }
        });

        // get the virtual name of the base directory
        String virtualFileStr = getAbsolutePath();
        if (virtualFileStr.charAt(virtualFileStr.length() - 1) != '/') {
            virtualFileStr += '/';
        }

        // now return all the files under the directory
        SshFile[] virtualFiles = new SshFile[files.length];
        for (int i = 0; i < files.length; ++i) {
            File fileObj = files[i];
            String fileName = virtualFileStr + fileObj.getName();
            virtualFiles[i] = new NativeSshFile(fileName, fileObj, userName);
        }

        return Collections.unmodifiableList(Arrays.asList(virtualFiles));
    }

    /**
     * Create output stream for writing.
     */
    public OutputStream createOutputStream(final long offset)
            throws IOException {

        // permission check
        if (!isWritable()) {
            throw new IOException("No write permission : " + file.getName());
        }

        // move to the appropriate offset and create output stream
        final RandomAccessFile raf = new RandomAccessFile(file, "rw");
        try {
            raf.setLength(offset);
            raf.seek(offset);

            // The IBM jre needs to have both the stream and the random access file
            // objects closed to actually close the file
            return new FileOutputStream(raf.getFD()) {
                public void close() throws IOException {
                    super.close();
                    raf.close();
                }
            };
        } catch (IOException e) {
            raf.close();
            throw e;
        }
    }

    /**
     * Create input stream for reading.
     */
    public InputStream createInputStream(final long offset) throws IOException {

        // permission check
        if (!isReadable()) {
            throw new IOException("No read permission : " + file.getName());
        }

        // move to the appropriate offset and create input stream
        final RandomAccessFile raf = new RandomAccessFile(file, "r");
        try {
            raf.seek(offset);

            // The IBM jre needs to have both the stream and the random access file
            // objects closed to actually close the file
            return new FileInputStream(raf.getFD()) {
                public void close() throws IOException {
                    super.close();
                    raf.close();
                }
            };
        } catch (IOException e) {
            raf.close();
            throw e;
        }
    }

    public void handleClose() {
        // Noop
    }

    /**
     * Normalize separate character. Separate character should be '/' always.
     */
    public final static String normalizeSeparateChar(final String pathName) {
        String normalizedPathName = pathName.replace(File.separatorChar, '/');
        normalizedPathName = normalizedPathName.replace('\\', '/');
        return normalizedPathName;
    }

    /**
     * Get the physical canonical file name. It works like
     * File.getCanonicalPath().
     * 
     * @param rootDir
     *            The root directory.
     * @param currDir
     *            The current directory. It will always be with respect to the
     *            root directory.
     * @param fileName
     *            The input file name.
     * @return The return string will always begin with the root directory. It
     *         will never be null.
     */
    public final static String getPhysicalName(final String rootDir,
            final String currDir, final String fileName) {
        return getPhysicalName(rootDir, currDir, fileName, false);
    }

    public final static String getPhysicalName(final String rootDir,
            final String currDir, final String fileName,
            final boolean caseInsensitive) {

        // get the starting directory
        String normalizedRootDir = normalizeSeparateChar(rootDir);
        if (normalizedRootDir.charAt(normalizedRootDir.length() - 1) != '/') {
            normalizedRootDir += '/';
        }

        String normalizedFileName = normalizeSeparateChar(fileName);
        String resArg;
        String normalizedCurrDir = currDir;
        if (normalizedFileName.charAt(0) != '/') {
            if (normalizedCurrDir == null) {
                normalizedCurrDir = "/";
            }
            if (normalizedCurrDir.length() == 0) {
                normalizedCurrDir = "/";
            }

            normalizedCurrDir = normalizeSeparateChar(normalizedCurrDir);

            if (normalizedCurrDir.charAt(0) != '/') {
                normalizedCurrDir = '/' + normalizedCurrDir;
            }
            if (normalizedCurrDir.charAt(normalizedCurrDir.length() - 1) != '/') {
                normalizedCurrDir += '/';
            }

            resArg = normalizedRootDir + normalizedCurrDir.substring(1);
        } else {
            resArg = normalizedRootDir;
        }

        // strip last '/'
        if (resArg.charAt(resArg.length() - 1) == '/') {
            resArg = resArg.substring(0, resArg.length() - 1);
        }

        // replace ., ~ and ..
        // in this loop resArg will never end with '/'
        StringTokenizer st = new StringTokenizer(normalizedFileName, "/");
        while (st.hasMoreTokens()) {
            String tok = st.nextToken();

            // . => current directory
            if (tok.equals(".")) {
                continue;
            }

            // .. => parent directory (if not root)
            if (tok.equals("..")) {
                if (resArg.startsWith(normalizedRootDir)) {
                    int slashIndex = resArg.lastIndexOf('/');
                    if (slashIndex != -1) {
                        resArg = resArg.substring(0, slashIndex);
                    }
                }
                continue;
            }

            // ~ => home directory (in this case the root directory)
            if (tok.equals("~")) {
                resArg = normalizedRootDir.substring(0, normalizedRootDir
                        .length() - 1);
                continue;
            }

            if (caseInsensitive) {
                File[] matches = new File(resArg)
                        .listFiles(new NameEqualsFileFilter(tok, true));

                if (matches != null && matches.length > 0) {
                    tok = matches[0].getName();
                }
            }

            resArg = resArg + '/' + tok;
        }

        // add last slash if necessary
        if ((resArg.length()) + 1 == normalizedRootDir.length()) {
            resArg += '/';
        }

        // final check
        if (!resArg.regionMatches(0, normalizedRootDir, 0, normalizedRootDir
                .length())) {
            resArg = normalizedRootDir;
        }

        return resArg;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj != null && obj instanceof NativeSshFile) {
            File thisCanonicalFile;
            File otherCanonicalFile;
            try {
                thisCanonicalFile = this.file.getCanonicalFile();
                otherCanonicalFile = ((NativeSshFile) obj).file
                        .getCanonicalFile();
            } catch (IOException e) {
                throw new RuntimeException("Failed to get the canonical path", e);
            }

            return thisCanonicalFile.equals(otherCanonicalFile);
        }
        return false;
    }
}
