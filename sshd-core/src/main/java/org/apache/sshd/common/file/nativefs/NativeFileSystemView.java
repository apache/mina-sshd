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

package org.apache.sshd.common.file.nativefs;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.sshd.common.file.FileSystemView;
import org.apache.sshd.common.file.SshFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.sshd.common.file.nativefs.NativeSshFile.normalizeSeparateChar;

/**
 * <strong>Internal class, do not use directly.</strong>
 * 
 * File system view based on native file system. Here the root directory will be
 * user virtual root (/).
 *
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class NativeFileSystemView implements FileSystemView {

    public enum UnsupportedAttributePolicy {
        Ignore,
        Warn,
        ThrowException
    }

    private final Logger LOG = LoggerFactory.getLogger(NativeFileSystemView.class);


    private Map<String, String> roots;

    // the first and the last character will always be '/'
    // It is always with respect to one of the roots.
    private String current;

    private String userName;

    private char separator;

    private boolean caseInsensitive = false;

    private UnsupportedAttributePolicy unsupportedAttributePolicy = UnsupportedAttributePolicy.Warn;

    /**
     * Constructor - internal do not use directly, use {@link NativeFileSystemFactory} instead
     */
    public NativeFileSystemView(String userName) {
        this(userName, false);
    }

    /**
     * Constructor - internal do not use directly, use {@link NativeFileSystemFactory} instead
     */
    public NativeFileSystemView(String userName, boolean caseInsensitive) {
        this(userName, getAllRoots(), System.getProperty("user.dir"), File.separatorChar, caseInsensitive);
    }

    /**
     * Constructor - internal do not use directly, use {@link NativeFileSystemFactory} instead
     */
    public NativeFileSystemView(String userName, Map<String, String> roots, String current) {
        this(userName, roots, current, File.separatorChar, false);
    }

    /**
     * Constructor - internal do not use directly, use {@link NativeFileSystemFactory} instead
     *
     * @param userName the user name
     * @param roots known root mapping, key is the virtual root name, value is the physical file
     * @param current the virtual current dir
     */
    public NativeFileSystemView(String userName, Map<String, String> roots, String current, char separator, boolean caseInsensitive) {
        if (userName == null) {
            throw new IllegalArgumentException("user can not be null");
        }
        // Normalize roots
        Map<String, String> verRoots = new LinkedHashMap<String, String>();
        for (String r : roots.keySet()) {
            String virtual = appendSlash(normalizeSeparateChar(r));
            String physical = appendSlash(normalizeSeparateChar(roots.get(r)));
            verRoots.put(virtual, physical);
        }
        // add last '/' if necessary
        current = appendSlash(normalizeSeparateChar(current));
        // Verify the current dir is relative to a known root
        String root = null;
        for (String r : verRoots.keySet()) {
            if (current.startsWith(r)) {
                root = r;
                break;
            }
        }
        if (root == null) {
            throw new IllegalArgumentException("Current dir " + current + " does not start from a known root: " + new ArrayList<String>(verRoots.keySet()));
        }

        this.separator = separator;
        this.caseInsensitive = caseInsensitive;
        this.roots = verRoots;
        this.current = current;
        this.userName = userName;
        LOG.debug("Native filesystem view created for user \"{}\" with current dir \"{}\"", userName, this.current);
    }

    private String appendSlash(String path) {
        return path.endsWith("/") ? path : path + "/";
    }

    private static Map<String, String> getAllRoots() {
        Map<String, String> roots = new LinkedHashMap<String, String>();
        if (isWindows) {
            for (File file : File.listRoots()) {
                if (file.exists()) {
                    String root = file.toString();
                    String name = root.substring(0, root.length() - 1);
                    roots.put(name, root);
                }
            }
        } else {
            roots.put("/", "/");
        }
        return roots;
    }

    public UnsupportedAttributePolicy getUnsupportedAttributePolicy() {
        return unsupportedAttributePolicy;
    }

    public void setUnsupportedAttributePolicy(UnsupportedAttributePolicy unsupportedAttributePolicy) {
        this.unsupportedAttributePolicy = unsupportedAttributePolicy;
    }

    public String getUserName() {
        return userName;
    }

    public char getSeparator() {
        return separator;
    }

    /**
     * Get file object.
     */
    public SshFile getFile(String file) {
        return getFile(current, file);
    }

    public SshFile getFile(SshFile baseDir, String file) {
        return getFile(baseDir.getAbsolutePath(), file);
    }

    protected SshFile getFile(String dir, String file) {
        dir = appendSlash(normalizeSeparateChar(dir));
        file = normalizeSeparateChar(file);
        // Compute root + non rooted absolute file
        String root = null;
        if (roots.size() > 1 && file.startsWith("/")) {
            file = file.substring(1);
        }
        for (String r : roots.keySet()) {
            if (!file.isEmpty() && r.equals(file + "/")) {
                file += "/";
            }
            if (file.startsWith(r)) {
                root = r;
                file = "/" + file.substring(r.length());
                break;
            }
        }
        if (root == null) {
            // file is relative to dir
            file = dir + file;
            for (String r : roots.keySet()) {
                if (file.startsWith(r)) {
                    root = r;
                    file = "/" + file.substring(r.length());
                    break;
                }
            }
        }
        if (root == null) {
            throw new IllegalStateException("Could not find root dir for file(" + dir + ", " + file + ")");
        }
        // Physical root
        String physicalRoot = roots.get(root);
        // get actual file object
        String physicalName = NativeSshFile.getPhysicalName(physicalRoot, "/", file, caseInsensitive);
        File fileObj = new File(physicalName);

        // strip the root directory and return
        String userFileName = root + physicalName.substring(physicalRoot.length());
        return createNativeSshFile(userFileName, fileObj, userName);
    }

    static boolean isJava7;
    static boolean isWindows;
    static {
        // Check java 7
        boolean j7 = false;
        try {
            ClassLoader.getSystemClassLoader().loadClass("java.nio.file.Files");
            j7 = true;
        } catch (Throwable t) {
            // Ignore
        }
        isJava7 = j7;
        // Check windows
        boolean win = false;
        try {
            win = System.getProperty("os.name").toLowerCase().contains("win");
        } catch (Throwable t) {
            // Ignore
        }
        isWindows = win;
    }

    public NativeSshFile createNativeSshFile(String name, File file, String userName) {
        name = deNormalizeSeparateChar(name);
        if (isJava7) {
            return new NativeSshFileNio(this, name, file, userName);
        } else {
		    return new NativeSshFile(this, name, file, userName);
        }
	}

    /**
     * Normalize separate character. Separate character should be '/' always.
     */
    public final String deNormalizeSeparateChar(final String pathName) {
        return pathName.replace('/', separator);
    }

    public FileSystemView getNormalizedView() {
        if (roots.size() == 1 && roots.containsKey("/") && separator == '/') {
            return this;
        }
        return new NativeFileSystemView(userName, roots, current, '/', caseInsensitive) {
            public SshFile getFile(String file) {
                return getFile(reroot(current), file);
            }

            public SshFile getFile(SshFile baseDir, String file) {
                return getFile(baseDir.getAbsolutePath(), file);
            }

            public FileSystemView getNormalizedView() {
                return this;
            }

            protected String reroot(String file) {
                file = appendSlash(file);
                for (String r : roots.keySet()) {
                    if (file.startsWith(r)) {
                        return "/" + normalizeRoot(r) + file.substring(r.length());
                    }
                }
                throw new IllegalArgumentException();
            }

            protected SshFile getFile(String dir, String file) {
                dir = appendSlash(normalizeSeparateChar(dir));
                file = normalizeSeparateChar(file);
                // Compute root + non rooted absolute file
                if (!file.startsWith("/")) {
                    file = dir + file;
                }
                // get actual file object
                String userFileName = NativeSshFile.getPhysicalName("/", "/", file, caseInsensitive);
                if (userFileName.equals("/")) {
                    return new RootFile();
                }
                int idx = userFileName.indexOf("/", 1);
                if (idx < 0) {
                    String root = userFileName + "/";
                    String physRoot = null;
                    for (String r : roots.keySet()) {
                        if (normalizeRoot(r).equals(root)) {
                            physRoot = roots.get(r);
                            break;
                        }
                    }
                    if (physRoot == null) {
                        throw new IllegalArgumentException("Unknown root " + userFileName);
                    }
                    File fileObj = new File(physRoot);
                    userFileName = normalizeSeparateChar(userFileName);
                    return createNativeSshFile(userFileName, fileObj, userName);
                } else {
                    String root = userFileName.substring(1, idx) + "/";
                    String physRoot = null;
                    for (String r : roots.keySet()) {
                        if (normalizeRoot(r).equals(root)) {
                            physRoot = roots.get(r);
                            break;
                        }
                    }
                    if (physRoot == null) {
                        throw new IllegalArgumentException("Unknown root " + userFileName);
                    }
                    File fileObj = new File(physRoot + userFileName.substring(idx + 1));
                    userFileName = normalizeSeparateChar(userFileName);
                    return createNativeSshFile(userFileName, fileObj, userName);
                }
            }
        };
    }

    protected static String normalizeRoot(String root) {
        return root.replace(":", "");
    }

    class RootFile implements SshFile {
        public String getAbsolutePath() {
            return "/";
        }
        public String getName() {
            return "/";
        }
        public Map<Attribute, Object> getAttributes(boolean followLinks) throws IOException {
            return null;
        }
        public void setAttributes(Map<Attribute, Object> attributes) throws IOException {
            throw new UnsupportedOperationException();
        }
        public Object getAttribute(Attribute attribute, boolean followLinks) throws IOException {
            return null;
        }
        public void setAttribute(Attribute attribute, Object value) throws IOException {
            throw new UnsupportedOperationException();
        }
        public String readSymbolicLink() throws IOException {
            return null;
        }
        public void createSymbolicLink(SshFile destination) throws IOException {
        }
        public String getOwner() {
            return null;
        }
        public boolean isDirectory() {
            return true;
        }
        public boolean isFile() {
            return false;
        }
        public boolean doesExist() {
            return true;
        }
        public boolean isReadable() {
            return true;
        }
        public boolean isWritable() {
            return false;
        }
        public boolean isExecutable() {
            return false;
        }
        public boolean isRemovable() {
            return false;
        }
        public SshFile getParentFile() {
            return null;
        }
        public long getLastModified() {
            return 0;
        }
        public boolean setLastModified(long time) {
            return false;
        }
        public long getSize() {
            return 0;
        }
        public boolean mkdir() {
            return false;
        }
        public boolean delete() {
            return false;
        }
        public boolean create() throws IOException {
            return false;
        }
        public void truncate() throws IOException {
        }
        public boolean move(SshFile destination) {
            return false;
        }
        public List<SshFile> listSshFiles() {
            List<SshFile> list = new ArrayList<SshFile>();
            for (String root : roots.keySet()) {
                String display = normalizeRoot(root);
                display = "/" + display.substring(display.length() - 1);
                list.add(createNativeSshFile(display, new File(roots.get(root)), userName));
            }
            return list;
        }
        public OutputStream createOutputStream(long offset) throws IOException {
            return null;
        }
        public InputStream createInputStream(long offset) throws IOException {
            return null;
        }
        public void handleClose() throws IOException {
        }
    }
}
