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

package org.apache.sshd.common.file.nativefs;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * Native file system factory. It uses the OS file system.
 *
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class NativeFileSystemFactory extends AbstractLoggingBean implements FileSystemFactory {
    public static final String DEFAULT_USERS_HOME = OsUtils.isWin32() ? "C:\\Users" : OsUtils.isOSX() ? "/Users" : "/home";

    public static final NativeFileSystemFactory INSTANCE = new NativeFileSystemFactory();

    private boolean createHome;
    private String usersHomeDir = DEFAULT_USERS_HOME;

    public NativeFileSystemFactory() {
        this(false);
    }

    public NativeFileSystemFactory(boolean createHome) {
        this.createHome = createHome;
    }

    /**
     * @return The root location where users home is to be created - never {@code null}/empty.
     */
    public String getUsersHomeDir() {
        return usersHomeDir;
    }

    /**
     * Set the root location where users home is to be created
     *
     * @param usersHomeDir The root location where users home is to be created - never {@code null}/empty.
     * @see                #isCreateHome()
     */
    public void setUsersHomeDir(String usersHomeDir) {
        this.usersHomeDir = ValidateUtils.checkNotNullAndNotEmpty(usersHomeDir, "No users home dir");
    }

    /**
     * Should the home directories be created automatically
     *
     * @return {@code true} if the file system will create the home directory if not available
     */
    public boolean isCreateHome() {
        return createHome;
    }

    /**
     * Set if the home directories be created automatically
     *
     * @param createHome {@code true} if the file system should create the home directory automatically if not available
     * @see              #getUsersHomeDir()
     */
    public void setCreateHome(boolean createHome) {
        this.createHome = createHome;
    }

    @Override
    public Path getUserHomeDir(SessionContext session) throws IOException {
        String userName = session.getUsername();
        if (GenericUtils.isEmpty(userName)) {
            return null;
        }

        String homeRoot = getUsersHomeDir();
        if (GenericUtils.isEmpty(homeRoot)) {
            return null;
        }

        return Paths.get(homeRoot, userName).normalize().toAbsolutePath();
    }

    @Override
    public FileSystem createFileSystem(SessionContext session) throws IOException {
        // create home if does not exist
        if (isCreateHome()) {
            Path homeDir = getUserHomeDir(session);
            if (homeDir == null) {
                throw new InvalidPathException(session.getUsername(), "Cannot resolve home directory");
            }

            if (Files.exists(homeDir)) {
                if (!Files.isDirectory(homeDir)) {
                    throw new NotDirectoryException(homeDir.toString());
                }
            } else {
                Path p = Files.createDirectories(homeDir);
                log.info("createFileSystem({}) created {}", session, p);
            }
        }

        return FileSystems.getDefault();
    }
}
