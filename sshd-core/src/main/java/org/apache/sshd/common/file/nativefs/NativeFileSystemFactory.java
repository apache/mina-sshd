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

import java.io.File;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;

import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * Native file system factory. It uses the OS file system.
 *
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class NativeFileSystemFactory extends AbstractLoggingBean implements FileSystemFactory {
    public static final NativeFileSystemFactory INSTANCE = new NativeFileSystemFactory();

    private boolean createHome;

    public NativeFileSystemFactory() {
        this(false);
    }

    public NativeFileSystemFactory(boolean createHome) {
        this.createHome = createHome;
    }

    /**
     * Should the home directories be created automatically
     *
     * @return true if the file system will create the home directory if not available
     */
    public boolean isCreateHome() {
        return createHome;
    }

    /**
     * Set if the home directories be created automatically
     *
     * @param createHome true if the file system will create the home directory if not available
     */
    public void setCreateHome(boolean createHome) {
        this.createHome = createHome;
    }

    @Override
    public FileSystem createFileSystem(Session session) {
        String userName = session.getUsername();
        // create home if does not exist
        if (createHome) {
            String homeDirStr = "/home/" + userName;
            File homeDir = new File(homeDirStr);
            if (homeDir.isFile()) {
                log.warn("Not a directory :: " + homeDirStr);
//                    throw new FtpException("Not a directory :: " + homeDirStr);
            }
            if ((!homeDir.exists()) && (!homeDir.mkdirs())) {
                log.warn("Cannot create user home :: " + homeDirStr);
//                    throw new FtpException("Cannot create user home :: "
//                            + homeDirStr);
            }
        }

        return FileSystems.getDefault();
    }

}
