/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.sftp.util;

import com.jcraft.jsch.UIKeyboardInteractive;
import com.jcraft.jsch.UserInfo;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SimpleUserInfo implements UserInfo, UIKeyboardInteractive {

    private final String password;

    public SimpleUserInfo(String password) {
        this.password = password;
    }

    public String getPassphrase() {
        return null;
    }

    public String getPassword() {
        return password;
    }

    public boolean promptPassword(String message) {
        return true;
    }

    public boolean promptPassphrase(String message) {
        return false;
    }

    public boolean promptYesNo(String message) {
        return true;
    }

    public void showMessage(String message) {
    }

    public String[] promptKeyboardInteractive(String destination, String name, String instruction, String[] prompt, boolean[] echo) {
        return new String[] { password };
    }
}
