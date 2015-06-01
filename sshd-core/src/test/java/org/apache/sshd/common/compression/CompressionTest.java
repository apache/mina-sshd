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
package org.apache.sshd.common.compression;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.apache.sshd.SshServer;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.util.BaseTestSupport;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.JSchLogger;
import org.apache.sshd.util.SimpleUserInfo;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Test;

import com.jcraft.jsch.JSch;

/**
 * Test compression algorithms.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CompressionTest extends BaseTestSupport {

    private SshServer sshd;

    @Test
    public void testCompNone() throws Exception {
        setUp(BuiltinCompressions.none);
        runTest();
    }

    @Test
    public void testCompZlib() throws Exception {
        setUp(BuiltinCompressions.zlib);
        runTest();
    }

    @Test
    public void testCompDelayedZlib() throws Exception {
        setUp(BuiltinCompressions.delayedZlib);
        runTest();
    }

    protected void setUp(NamedFactory<org.apache.sshd.common.compression.Compression> compression) throws Exception {
        sshd = SshServer.setUpDefaultServer();
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setCompressionFactories(Arrays.<NamedFactory<org.apache.sshd.common.compression.Compression>>asList(compression));
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(BogusPasswordAuthenticator.INSTANCE);
        sshd.start();
        JSch.setConfig("compression.s2c",  "zlib@openssh.com,zlib,none");
        JSch.setConfig("compression.c2s",  "zlib@openssh.com,zlib,none");
        JSch.setConfig("zlib",             com.jcraft.jsch.jcraft.Compression.class.getName());
        JSch.setConfig("zlib@openssh.com", com.jcraft.jsch.jcraft.Compression.class.getName());
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
        JSch.setConfig("compression.s2c", "none");
        JSch.setConfig("compression.c2s", "none");
    }

    protected void runTest() throws Exception {
        JSchLogger.init();
        JSch sch = new JSch();
        com.jcraft.jsch.Session s = sch.getSession(getCurrentTestName(), "localhost", sshd.getPort());
        s.setUserInfo(new SimpleUserInfo(getCurrentTestName()));

        s.connect();
        try {
            com.jcraft.jsch.Channel c = s.openChannel("shell");
            c.connect();
            try(OutputStream os = c.getOutputStream();
                 InputStream is = c.getInputStream()) {
                final String    STR="this is my command\n";
                final byte[]    bytes=STR.getBytes(StandardCharsets.UTF_8);
                byte[]          data=new byte[bytes.length + Long.SIZE];
                for (int i = 0; i < 10; i++) {
                    os.write(bytes);
                    os.flush();

                    int len = is.read(data);
                    String str = new String(data, 0, len, StandardCharsets.UTF_8);
                    assertEquals("Mismatched read data at iteration #" + i, STR, str);
                }
            } finally {
                c.disconnect();
            } 
        } finally {
            s.disconnect();
        }
    }
}
