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
package org.apache.sshd.common.file.virtualfs;

import java.io.File;
import java.io.IOException;

import org.apache.sshd.SshServer;
import org.apache.sshd.common.AbstractFactoryManager;
import org.apache.sshd.common.file.FileSystemView;
import org.apache.sshd.common.file.SshFile;
import org.apache.sshd.common.file.nativefs.NativeFileSystemFactory;
import org.apache.sshd.common.file.nativefs.NativeSshFile;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.util.BaseTest;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class VirtualFileSystemTest extends BaseTest {

    @Test
    public void testNativeFileSystem() throws IOException {
        String homeDir = System.getProperty("user.dir");
        NativeFileSystemFactory vfs = new NativeFileSystemFactory();

        FileSystemView view = vfs.createFileSystemView(new TestSession());

        SshFile file = view.getFile("foo");
        String physicalName = ((NativeSshFile) file).getNativeFile().getAbsolutePath();
        assertEquals(homeDir + File.separator + "foo", physicalName);

        file = view.getFile(view.getFile("foo"), "../bar");
        physicalName = ((NativeSshFile) file).getNativeFile().getAbsolutePath();
        assertEquals(homeDir + File.separator + "bar", physicalName);

        file = view.getFile("../bar");
        physicalName = ((NativeSshFile) file).getNativeFile().getAbsolutePath();
        assertEquals(new File(homeDir, "../bar").getCanonicalPath(), physicalName);
    }

    @Test
    public void testVirtualFileSystem() {
        String homeDir = System.getProperty("user.dir");
        VirtualFileSystemFactory vfs = new VirtualFileSystemFactory(homeDir);

        FileSystemView view = vfs.createFileSystemView(new TestSession());

        SshFile file = view.getFile("foo");
        String physicalName = ((NativeSshFile) file).getNativeFile().getAbsolutePath();
        assertEquals(homeDir + File.separator + "foo", physicalName);

        file = view.getFile(view.getFile("foo"), "../bar");
        physicalName = ((NativeSshFile) file).getNativeFile().getAbsolutePath();
        assertEquals(homeDir + File.separator + "bar", physicalName);

        file = view.getFile("../bar");
        physicalName = ((NativeSshFile) file).getNativeFile().getAbsolutePath();
        assertEquals(homeDir + File.separator + "bar", physicalName);
    }

    static class TestSession extends AbstractSession {
        TestSession() {
            super(true, SshServer.setUpDefaultServer(), null);
            this.username = "userName";
        }
        @Override
        protected void handleMessage(Buffer buffer) throws Exception {
        }
        @Override
        protected boolean readIdentification(Buffer buffer) throws IOException {
            return false;
        }
        @Override
        protected void sendKexInit() throws IOException {
        }
        @Override
        protected void checkKeys() {
        }
        @Override
        protected void receiveKexInit(Buffer buffer) throws IOException {
        }
        @Override
        public void startService(String name) throws Exception {
        }
        @Override
        public void resetIdleTimeout() {
        }
    }

    static class TestFactoryManager extends AbstractFactoryManager {

    }
}
