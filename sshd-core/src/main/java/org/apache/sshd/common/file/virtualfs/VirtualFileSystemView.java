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
package org.apache.sshd.common.file.virtualfs;

import java.io.File;

import org.apache.sshd.common.file.SshFile;
import org.apache.sshd.common.file.nativefs.NativeFileSystemView;
import org.apache.sshd.common.file.nativefs.NativeSshFile;

/**
 * Virtual file system view reduced to a physical folder
 */
public class VirtualFileSystemView extends NativeFileSystemView {

    private String location;

    public VirtualFileSystemView(String username, String location) {
        super(username);
        if (location.endsWith("/")) {
            location = location.substring(0, location.length() - 1);
        }
        this.location = location;
    }

    @Override
    public String getVirtualUserDir() {
        return "/";
    }

    @Override
    public String getPhysicalUserDir() {
        return location;
    }

    @Override
    protected SshFile getFile(String dir, String file) {
        // get actual file object
        String location = getPhysicalUserDir();
        String physicalName = NativeSshFile.getPhysicalName(location, dir, file, false);
        File fileObj = new File(physicalName);
        // strip the root directory and return
        String karafFileName = physicalName.substring(location.length());
        return createNativeSshFile(karafFileName, fileObj, getUserName());
    }

}
