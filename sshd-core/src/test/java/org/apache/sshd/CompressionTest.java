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
package org.apache.sshd;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Logger;
import com.jcraft.jsch.UserInfo;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.compression.CompressionDelayedZlib;
import org.apache.sshd.common.compression.CompressionNone;
import org.apache.sshd.common.compression.CompressionZlib;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.junit.After;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

/**
 * Test compression algorithms.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CompressionTest {

    private SshServer sshd;

    @Test
    public void testCompNone() throws Exception {
        setUp(new CompressionNone.Factory());
        runTest();
    }

    @Test
    public void testCompZlib() throws Exception {
        setUp(new CompressionZlib.Factory());
        runTest();
    }

    @Test
    public void testCompDelayedZlib() throws Exception {
        setUp(new CompressionDelayedZlib.Factory());
        runTest();
    }


    protected void setUp(NamedFactory<org.apache.sshd.common.Compression> compression) throws Exception {
        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(8000);
        sshd.setKeyPairProvider(new FileKeyPairProvider(new String[] { "src/test/resources/hostkey.pem" }));
        sshd.setCompressionFactories(Arrays.<NamedFactory<org.apache.sshd.common.Compression>>asList(compression));
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.start();
        JSch.setConfig("compression.s2c",  "zlib@openssh.com,zlib,none");
        JSch.setConfig("compression.c2s",  "zlib@openssh.com,zlib,none");
        JSch.setConfig("zlib",             org.apache.sshd.util.Compression.class.getName());
        JSch.setConfig("zlib@openssh.com", org.apache.sshd.util.Compression.class.getName());
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop();
            Thread.sleep(50);
        }
        JSch.setConfig("compression.s2c", "none");
        JSch.setConfig("compression.c2s", "none");
    }

    protected void runTest() throws Exception {
        JSch sch = new JSch();
        sch.setLogger(new Logger() {
            public boolean isEnabled(int i) {
                return true;
            }
            public void log(int i, String s) {
                System.out.println("Log(jsch," + i + "): " + s);
            }
        });
        com.jcraft.jsch.Session s = sch.getSession("smx", "localhost", 8000);
        s.setUserInfo(new UserInfo() {
            public String getPassphrase() {
                return null;
            }
            public String getPassword() {
                return "smx";
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
        });
        s.connect();
        com.jcraft.jsch.Channel c = s.openChannel("shell");
        c.connect();
        OutputStream os = c.getOutputStream();
        InputStream is = c.getInputStream();
        for (int i = 0; i < 10; i++) {
            os.write("this is my command\n".getBytes());
            os.flush();
            byte[] data = new byte[512];
            int len = is.read(data);
            String str = new String(data, 0, len);
            assertEquals("this is my command\n", str);
        }
        c.disconnect();
        s.disconnect();
    }
}
