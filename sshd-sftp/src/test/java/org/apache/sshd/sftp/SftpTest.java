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
package org.apache.sshd.sftp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Vector;

import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Logger;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.sftp.subsystem.SftpSubsystem;
import org.apache.sshd.sftp.util.BogusPasswordAuthenticator;
import org.apache.sshd.sftp.util.EchoShellFactory;
import org.apache.sshd.sftp.util.JSchLogger;
import org.apache.sshd.sftp.util.SimpleUserInfo;
import org.apache.sshd.sftp.util.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SftpTest {

    private SshServer sshd;
    private int port;
    private com.jcraft.jsch.Session session;

    @Before
    public void setUp() throws Exception {
        port = Utils.getFreePort();

        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystem.Factory()));
        sshd.setCommandFactory(new ScpCommandFactory());
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.start();

        JSchLogger.init();
        JSch sch = new JSch();
        session = sch.getSession("sshd", "localhost", port);
        session.setUserInfo(new SimpleUserInfo("sshd"));
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

    /*
     * TODO: upgrade to a more recent version of ganymed to be able to test that

    @Test
    public void testBigFileWithGanymed() throws Exception {
        final Connection conn = new Connection("localhost", port);
        conn.connect(null, 5000, 0);
        conn.authenticateWithPassword("sshd", "sshd");
        final SFTPv3Client sftp_client = new SFTPv3Client(conn);

        StringBuilder sb = new StringBuilder();
        for (int i = 1; i < 1000; i++) {
            sb.append("0123456789");
            if (i % 10 == 0) {
                sb.append("\n");
            }
        }
        sb.append("\n");
        byte[] buffer = sb.toString().getBytes();

        // Upload

        SFTPv3FileHandle handle = sftp_client.openFileRW("target/bigfile.txt");

        long offset = 0;
        for (int i = 0; i < 100; i++) {
            sftp_client.write(handle, offset, buffer, 0, buffer.length);
            offset += buffer.length;
        }

        sftp_client.closeFile(handle);

        handle = sftp_client.openFileRW("target/bigfile.txt");

        offset = 0;
        buffer = new byte[32768];
        for (;;) {
            int len = sftp_client.read(handle, offset, buffer, 0, buffer.length);
            if (len >= 0) {
                offset += len;
            } else {
                break;
            }
        }

        sftp_client.closeFile(handle);

        sftp_client.close();

    }
    */

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

    public static void main(String[] args) throws Exception {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(8001);
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystem.Factory()));
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setCommandFactory(new ScpCommandFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.start();
        Thread.sleep(100000);
    }

}
