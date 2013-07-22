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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Vector;

import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Logger;
import com.jcraft.jsch.UserInfo;
import org.apache.sshd.client.SftpClient;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.server.sftp.SftpSubsystem;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SftpTest {

    private SshServer sshd;
    private int port;
    private com.jcraft.jsch.Session session;

    @Before
    public void setUp() throws Exception {
        ServerSocket s = new ServerSocket(0);
        port = s.getLocalPort();
        s.close();

        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystem.Factory()));
        sshd.setCommandFactory(new ScpCommandFactory());
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.start();

        JSch sch = new JSch();
        sch.setLogger(new Logger() {
            public boolean isEnabled(int i) {
                return true;
            }

            public void log(int i, String s) {
                System.out.println("Log(jsch," + i + "): " + s);
            }
        });
        session = sch.getSession("sshd", "localhost", port);
        session.setUserInfo(new UserInfo() {
            public String getPassphrase() {
                return null;
            }

            public String getPassword() {
                return "sshd";
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
        session.connect();
    }

    @After
    public void tearDown() throws Exception {
        session.disconnect();
        sshd.stop();
    }

    @Test
    @Ignore
    public void testExternal() throws Exception {
        System.out.println("SFTP subsystem available on port " + port);
        Thread.sleep(5 * 60000);
    }

    @Test
    public void testClient() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("x", "x").await();

        new File("target/scp").mkdirs();
        new File("target/scp/client/test.txt").delete();
        new File("target/scp/client").delete();

        SftpClient sftp = session.createSftpClient();

        sftp.mkdir("target/scp/client");

        SftpClient.Handle h = sftp.open("target/scp/client/test.txt", EnumSet.of(SftpClient.OpenMode.Write));
        byte[] d = "0123456789\n".getBytes();
        sftp.write(h, 0, d, 0, d.length);
        sftp.write(h, d.length, d, 0, d.length);

        SftpClient.Attributes attrs = sftp.stat(h);
        Assert.assertNotNull(attrs);

        sftp.close(h);

        h = sftp.openDir("target/scp/client");
        SftpClient.DirEntry[] dir = sftp.readDir(h);
        assertNotNull(dir);
        assertEquals(1, dir.length);
        assertNull(sftp.readDir(h));
        sftp.close(h);

        sftp.remove("target/scp/client/test.txt");

        OutputStream os = sftp.write("target/scp/client/test.txt");
        os.write(new byte[1024 * 128]);
        os.close();

        InputStream is = sftp.read("target/scp/client/test.txt");
        is.read(new byte[1024 * 128]);
        int i = is.read();
        is.close();

        int nb = 0;
        for (SftpClient.DirEntry entry : sftp.readDir("target/scp/client")) {
            nb++;
        }
        assertEquals(1, nb);

        sftp.remove("target/scp/client/test.txt");

        sftp.rmdir("target/scp/client/");

        client.stop();
    }

    @Test
    public void testSftp() throws Exception {
        String d = "0123456789\n";

        File root = new File("target/scp");
        File target = new File("target/scp/out.txt");
        root.mkdirs();
        assertTrue(root.exists());

        for (int j = 10; j <= 10; j++) {
            String data = "";
            for (int i = 0; i < j; i++) {
                data = data + d;
            }

            target.delete();
            assertFalse(target.exists());
            sendFile("target/scp/out.txt", data);
            assertFileLength(target, data.length(), 5000);

            target.delete();
            assertFalse(target.exists());
        }
        root.delete();
    }

    @Test
    public void testReadWriteWithOffset() throws Exception {
        File root = new File("target/scp");
        String unixPath = "target/scp/out.txt";
        File target = new File(unixPath);
        root.mkdirs();
        assertTrue(root.exists());

        ChannelSftp c = (ChannelSftp) session.openChannel("sftp");
        c.connect();
        c.put(new ByteArrayInputStream("0123456789".getBytes()), unixPath);

        assertTrue(target.exists());
        assertEquals("0123456789", readFile(unixPath));

        OutputStream os = c.put(unixPath, null, ChannelSftp.APPEND, -5);
        os.write("a".getBytes());
        os.close();
        c.disconnect();

        assertTrue(target.exists());
        assertEquals("01234a", readFile(unixPath));

        target.delete();
        assertFalse(target.exists());
        root.delete();
    }

    @Test
    public void testReadDir() throws Exception {
        ChannelSftp c = (ChannelSftp) session.openChannel("sftp");
        c.connect();
        Vector res = c.ls("target/classes/org/apache/sshd/");
        for (Object f : res) {
            System.out.println(f.toString());
        }
    }

    protected void assertFileLength(File file, long length, long timeout) throws Exception {
        boolean ok = false;
        while (timeout > 0) {
            if (file.exists() && file.length() == length) {
                if (!ok) {
                    ok = true;
                } else {
                    return;
                }
            } else {
                ok = false;
            }
            Thread.sleep(100);
            timeout -= 100;
        }
        assertTrue(file.exists());
        assertEquals(length, file.length());
    }

    protected String readFile(String path) throws Exception {
        ChannelSftp c = (ChannelSftp) session.openChannel("sftp");
        c.connect();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        InputStream is = c.get(path);
        try {
            byte[] buffer = new byte[256];
            int count;
            while (-1 != (count = is.read(buffer))) {
                bos.write(buffer, 0, count);
            }
        } finally {
            is.close();
        }

        c.disconnect();
        return new String(bos.toByteArray());
    }

    protected void sendFile(String path, String data) throws Exception {
        ChannelSftp c = (ChannelSftp) session.openChannel("sftp");
        c.connect();
        c.put(new ByteArrayInputStream(data.getBytes()), path);
        c.disconnect();
    }

}
