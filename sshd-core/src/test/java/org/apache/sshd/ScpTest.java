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

import java.net.ServerSocket;
import java.io.OutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.IOException;
import java.io.ByteArrayOutputStream;

import org.junit.Before;
import org.junit.After;
import org.junit.Test;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.server.command.ScpCommandFactory;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Logger;
import com.jcraft.jsch.UserInfo;
import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelExec;

import static org.junit.Assert.*;

/**
 * Test for SCP support.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpTest {

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
        sshd.setKeyPairProvider(new FileKeyPairProvider(new String[] { "src/test/resources/hostkey.pem" }));
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
    public void testScp() throws Exception {
        String data = "0123456789\n";

        File root = new File("target/scp");
        File target = new File("target/scp/out.txt");
        root.mkdirs();
        assertTrue(root.exists());

        target.delete();
        assertFalse(target.exists());
        sendFile("target/scp/out.txt", "out.txt", data);
        Thread.sleep(100);
        assertTrue(target.exists());
        assertEquals(data.length(), target.length());

        target.delete();
        assertFalse(target.exists());
        sendFile("target/scp", "out.txt", data);
        Thread.sleep(100);
        assertTrue(target.exists());
        assertEquals(data.length(), target.length());

        sendFileError("target", "scp", "0123456789\n");

        readFileError("target/scp");

        assertEquals(data, readFile("target/scp/out.txt"));

        assertEquals(data, readDir("target/scp"));

        target.delete();
        root.delete();

        sendDir("target", "scp", "out.txt", data);
        Thread.sleep(100);
        assertTrue(target.exists());
        assertEquals(data.length(), target.length());
    }

    protected String readFile(String path) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel("exec");
        c.setCommand("scp -f " + path);
        c.connect();
        OutputStream os = c.getOutputStream();
        InputStream is = c.getInputStream();
        String header = readLine(is);
        assertEquals("C0644 11 out.txt", header);
        int length = Integer.parseInt(header.substring(6, header.indexOf(' ', 6)));
        os.write(0);
        os.flush();

        byte[] buffer = new byte[length];
        length = is.read(buffer, 0, buffer.length);
        assertEquals(length, buffer.length);
        assertEquals(0, is.read());
        os.write(0);
        os.flush();

        c.disconnect();
        return new String(buffer);
    }

    protected String readDir(String path) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel("exec");
        c.setCommand("scp -f -r " + path);
        c.connect();
        OutputStream os = c.getOutputStream();
        InputStream is = c.getInputStream();
        String header = readLine(is);
        assertTrue(header.startsWith("D0755 0 "));
        os.write(0);
        os.flush();
        header = readLine(is);
        assertEquals("C0644 11 out.txt", header);
        int length = Integer.parseInt(header.substring(6, header.indexOf(' ', 6)));
        os.write(0);
        os.flush();
        byte[] buffer = new byte[length];
        length = is.read(buffer, 0, buffer.length);
        assertEquals(length, buffer.length);
        assertEquals(0, is.read());
        os.write(0);
        os.flush();
        header = readLine(is);
        assertEquals("E", header);

        c.disconnect();
        return new String(buffer);
    }

    protected String readFileError(String path) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel("exec");
        c.setCommand("scp -f " + path);
        c.connect();
        OutputStream os = c.getOutputStream();
        InputStream is = c.getInputStream();
        assertEquals(2, is.read());
        c.disconnect();
        return null;
    }

    protected void sendFile(String path, String name, String data) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel("exec");
        c.setCommand("scp -t " + path);
        c.connect();
        OutputStream os = c.getOutputStream();
        InputStream is = c.getInputStream();
        os.write(("C7777 "+ data.length() + " " + name + "\n").getBytes());
        os.flush();
        assertEquals(0, is.read());
        os.write(data.getBytes());
        os.flush();
        assertEquals(0, is.read());
        os.write(0);
        os.flush();
        c.disconnect();
    }

    protected void sendFileError(String path, String name, String data) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel("exec");
        c.setCommand("scp -t " + path);
        c.connect();
        OutputStream os = c.getOutputStream();
        InputStream is = c.getInputStream();
        os.write(("C7777 "+ data.length() + " " + name + "\n").getBytes());
        os.flush();
        assertEquals(0, is.read());
        os.write(data.getBytes());
        os.flush();
        assertEquals(2, is.read());
        c.disconnect();
    }

    protected void sendDir(String path, String dirName, String fileName, String data) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel("exec");
        c.setCommand("scp -t -r " + path);
        c.connect();
        OutputStream os = c.getOutputStream();
        InputStream is = c.getInputStream();

        os.write(("D0755 0 " + dirName + "\n").getBytes());
        os.flush();
        assertEquals(0, is.read());
        os.write(("C7777 "+ data.length() + " " + fileName + "\n").getBytes());
        os.flush();
        assertEquals(0, is.read());
        os.write(data.getBytes());
        os.flush();
        assertEquals(0, is.read());
        os.write(0);
        os.flush();
        os.write("E\n".getBytes());
        assertEquals(0, is.read());
    }

    private String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (;;) {
            int c = in.read();
            if (c == '\n') {
                return baos.toString();
            } else if (c == -1) {
                throw new IOException("End of stream");
            } else {
                baos.write(c);
            }
        }
    }

}
