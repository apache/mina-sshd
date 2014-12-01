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
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;

import org.apache.sshd.common.Session;
import org.apache.sshd.common.file.FileSystemFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Native file system factory. It uses the OS file system.
 *
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */
public class NativeFileSystemFactory implements FileSystemFactory {

    private final Logger LOG = LoggerFactory.getLogger(NativeFileSystemFactory.class);

    private boolean createHome;

    /**
     * Should the home directories be created automatically
     * @return true if the file system will create the home directory if not available
     */
    public boolean isCreateHome() {
        return createHome;
    }

    /**
     * Set if the home directories be created automatically
     * @param createHome true if the file system will create the home directory if not available
     */

    public void setCreateHome(boolean createHome) {
        this.createHome = createHome;
    }

    /**
     * Create the appropriate user file system view.
     */
    public FileSystem createFileSystem(Session session) {
        String userName = session.getUsername();
        // create home if does not exist
        if (createHome) {
            String homeDirStr = "/home/" + userName;
            File homeDir = new File(homeDirStr);
            if (homeDir.isFile()) {
                LOG.warn("Not a directory :: " + homeDirStr);
//                    throw new FtpException("Not a directory :: " + homeDirStr);
            }
            if ((!homeDir.exists()) && (!homeDir.mkdirs())) {
                LOG.warn("Cannot create user home :: " + homeDirStr);
//                    throw new FtpException("Cannot create user home :: "
//                            + homeDirStr);
            }
        }

        return FileSystems.getDefault();
    }

}
