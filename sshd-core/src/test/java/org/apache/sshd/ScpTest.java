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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import ch.ethz.ssh2.Connection;
import ch.ethz.ssh2.SCPClient;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import org.apache.sshd.client.ScpClient;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.util.BaseTest;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.JSchLogger;
import org.apache.sshd.util.SimpleUserInfo;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Test for SCP support.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpTest extends BaseTest {

    private SshServer sshd;
    private int port;
    private com.jcraft.jsch.Session session;

    @Before
    public void setUp() throws Exception {
        port = Utils.getFreePort();
//        port = 8102;

        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setCommandFactory(new ScpCommandFactory());
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.start();
    }

    protected com.jcraft.jsch.Session getJschSession() throws JSchException {
        JSchLogger.init();
        JSch sch = new JSch();
        session = sch.getSession("sshd", "localhost", port);
        session.setUserInfo(new SimpleUserInfo("sshd"));
        session.connect();
        return session;
    }

    @After
    public void tearDown() throws Exception {
        if (session != null) {
            session.disconnect();
        }
        sshd.stop();
    }

    @Test
    @Ignore
    public void testExternal() throws Exception {
        System.out.println("Scp available on port " + port);
        Thread.sleep(5 * 60000);
    }

    @Test
    public void testUploadAbsoluteDriveLetter() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("test", "test").await();

        ScpClient scp = session.createScpClient();

        String data = "0123456789\n";

        File root = new File("target/scp");
        Utils.deleteRecursive(root);
        root.mkdirs();
        new File(root, "local").mkdirs();
        assertTrue(root.exists());


        writeFile(new File("target/scp/local/out.txt"), data);
        new File(root, "remote").mkdirs();
        scp.upload(new File("target/scp/local/out.txt").getAbsolutePath(), "/" + new File("target/scp/remote/out.txt").getAbsolutePath().replace(File.separatorChar, '/'));
        assertFileLength(new File("target/scp/remote/out.txt"), data.length(), 5000);
        scp.upload(new File("target/scp/local/out.txt").getAbsolutePath(), new File("target/scp/remote/out2.txt").getAbsolutePath());
        assertFileLength(new File("target/scp/remote/out2.txt"), data.length(), 5000);
    }

    @Test
    public void testScpNativeOnSingleFile() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("test", "test").await();

        ScpClient scp = session.createScpClient();

        String data = "0123456789\n";

        File root = new File("target/scp");
        Utils.deleteRecursive(root);
        root.mkdirs();
        new File(root, "local").mkdirs();
        assertTrue(root.exists());


        writeFile(new File("target/scp/local/out.txt"), data);
        try {
            scp.upload("target/scp/local/out.txt", "target/scp/remote/out.txt");
            fail("Expected IOException");
        } catch (IOException e) {
            // ok
        }
        new File(root, "remote").mkdirs();
        scp.upload("target/scp/local/out.txt", "target/scp/remote/out.txt");
        assertFileLength(new File("target/scp/remote/out.txt"), data.length(), 5000);

        scp.download("target/scp/remote/out.txt", "target/scp/local/out2.txt");
        assertFileLength(new File("target/scp/local/out2.txt"), data.length(), 5000);

        session.close(false).await();
        client.stop();
    }

    @Test
    public void testScpNativeOnMultipleFiles() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("test", "test").await();

        ScpClient scp = session.createScpClient();

        String data = "0123456789\n";

        File root = new File("target/scp");
        Utils.deleteRecursive(root);
        root.mkdirs();
        new File(root, "local").mkdirs();
        new File(root, "remote").mkdirs();
        assertTrue(root.exists());


        writeFile(new File("target/scp/local/out1.txt"), data);
        writeFile(new File("target/scp/local/out2.txt"), data);
        try {
            scp.upload(new String[] { "target/scp/local/out1.txt", "target/scp/local/out2.txt" }, "target/scp/remote/out.txt");
            fail("Expected IOException");
        } catch (IOException e) {
            // Ok
        }
        writeFile(new File("target/scp/remote/out.txt"), data);
        try {
            scp.upload(new String[] { "target/scp/local/out1.txt", "target/scp/local/out2.txt" }, "target/scp/remote/out.txt");
            fail("Expected IOException");
        } catch (IOException e) {
            // Ok
        }
        new File(root, "remote/dir").mkdirs();
        scp.upload(new String[] { "target/scp/local/out1.txt", "target/scp/local/out2.txt" }, "target/scp/remote/dir");
        assertFileLength(new File("target/scp/remote/dir/out1.txt"), data.length(), 5000);
        assertFileLength(new File("target/scp/remote/dir/out2.txt"), data.length(), 5000);

        try {
            scp.download(new String[] { "target/scp/remote/dir/out1.txt", "target/scp/remote/dir/out2.txt" }, "target/scp/local/out1.txt");
            fail("Expected IOException");
        } catch (IOException e) {
            // Ok
        }
        try {
            scp.download(new String[] { "target/scp/remote/dir/out1.txt", "target/scp/remote/dir/out2.txt" }, "target/scp/local/dir");
            fail("Expected IOException");
        } catch (IOException e) {
            // Ok
        }
        new File(root, "local/dir").mkdirs();
        scp.download(new String[] { "target/scp/remote/dir/out1.txt", "target/scp/remote/dir/out2.txt" }, "target/scp/local/dir");
        assertFileLength(new File("target/scp/local/dir/out1.txt"), data.length(), 5000);
        assertFileLength(new File("target/scp/local/dir/out2.txt"), data.length(), 5000);

        session.close(false).await();
        client.stop();
    }

    @Test
    public void testScpNativeOnRecursiveDirs() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("test", "test").await();

        ScpClient scp = session.createScpClient();

        String data = "0123456789\n";

        File root = new File("target/scp");
        Utils.deleteRecursive(root);
        root.mkdirs();
        new File(root, "local").mkdirs();
        new File(root, "remote").mkdirs();
        assertTrue(root.exists());

        new File("target/scp/local/dir").mkdirs();
        writeFile(new File("target/scp/local/dir/out1.txt"), data);
        writeFile(new File("target/scp/local/dir/out2.txt"), data);
        scp.upload("target/scp/local/dir", "target/scp/remote/", ScpClient.Option.Recursive);
        assertFileLength(new File("target/scp/remote/dir/out1.txt"), data.length(), 5000);
        assertFileLength(new File("target/scp/remote/dir/out2.txt"), data.length(), 5000);

        Utils.deleteRecursive(new File("target/scp/local/dir"));
        scp.download("target/scp/remote/dir", "target/scp/local", ScpClient.Option.Recursive);
        assertFileLength(new File("target/scp/local/dir/out1.txt"), data.length(), 5000);
        assertFileLength(new File("target/scp/local/dir/out2.txt"), data.length(), 5000);

        session.close(false).await();
        client.stop();
    }

    @Test
    public void testScpNativeOnDirWithPattern() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("test", "test").await();

        ScpClient scp = session.createScpClient();

        String data = "0123456789\n";

        File root = new File("target/scp");
        Utils.deleteRecursive(root);
        root.mkdirs();
        new File(root, "local").mkdirs();
        new File(root, "remote").mkdirs();
        assertTrue(root.exists());

        writeFile(new File("target/scp/local/out1.txt"), data);
        writeFile(new File("target/scp/local/out2.txt"), data);
        scp.upload("target/scp/local/*", "target/scp/remote/");
        assertFileLength(new File("target/scp/remote/out1.txt"), data.length(), 5000);
        assertFileLength(new File("target/scp/remote/out2.txt"), data.length(), 5000);

        new File("target/scp/local/out1.txt").delete();
        new File("target/scp/local/out2.txt").delete();
        scp.download("target/scp/remote/*", "target/scp/local");
        assertFileLength(new File("target/scp/local/out1.txt"), data.length(), 5000);
        assertFileLength(new File("target/scp/local/out2.txt"), data.length(), 5000);

        session.close(false).await();
        client.stop();
    }

    @Test
    public void testScpNativeOnMixedDirAndFiles() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("test", "test").await();

        ScpClient scp = session.createScpClient();

        String data = "0123456789\n";

        File root = new File("target/scp");
        Utils.deleteRecursive(root);
        root.mkdirs();
        new File(root, "local").mkdirs();
        new File(root, "remote").mkdirs();
        assertTrue(root.exists());

        new File("target/scp/local/dir").mkdirs();
        writeFile(new File("target/scp/local/out1.txt"), data);
        writeFile(new File("target/scp/local/dir/out2.txt"), data);
        scp.upload("target/scp/local/*", "target/scp/remote/", ScpClient.Option.Recursive);
        assertFileLength(new File("target/scp/remote/out1.txt"), data.length(), 5000);
        assertFileLength(new File("target/scp/remote/dir/out2.txt"), data.length(), 5000);

        Utils.deleteRecursive(new File("target/scp/local/out1.txt"));
        Utils.deleteRecursive(new File("target/scp/local/dir"));
        scp.download("target/scp/remote/*", "target/scp/local");
        assertFileLength(new File("target/scp/local/out1.txt"), data.length(), 5000);
        assertFalse(new File("target/scp/local/dir/out2.txt").exists());

        Utils.deleteRecursive(new File("target/scp/local/out1.txt"));
        scp.download("target/scp/remote/*", "target/scp/local", ScpClient.Option.Recursive);
        assertFileLength(new File("target/scp/local/out1.txt"), data.length(), 5000);
        assertFileLength(new File("target/scp/local/dir/out2.txt"), data.length(), 5000);

        session.close(false).await();
        client.stop();
    }

    @Test
    public void testScpNativePreserveAttributes() throws Exception {
        // Ignore this test if running a Windows system
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            return;
        }

        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port).await().getSession();
        session.authPassword("test", "test").await();

        ScpClient scp = session.createScpClient();

        String data = "0123456789\n";

        File root = new File("target/scp");
        Utils.deleteRecursive(root);
        root.mkdirs();
        new File(root, "local").mkdirs();
        new File(root, "remote").mkdirs();
        assertTrue(root.exists());

        new File("target/scp/local/dir").mkdirs();
        long lastMod = new File("target/scp/local/dir").lastModified() - TimeUnit.DAYS.toMillis(1);

        writeFile(new File("target/scp/local/out1.txt"), data);
        writeFile(new File("target/scp/local/dir/out2.txt"), data);
        new File("target/scp/local/out1.txt").setLastModified(lastMod);
        new File("target/scp/local/out1.txt").setExecutable(true, true);
        new File("target/scp/local/out1.txt").setWritable(false, false);
        new File("target/scp/local/dir/out2.txt").setLastModified(lastMod);
        scp.upload("target/scp/local/*", "target/scp/remote/", ScpClient.Option.Recursive, ScpClient.Option.PreserveAttributes);
        assertFileLength(new File("target/scp/remote/out1.txt"), data.length(), 5000);
        assertEquals(lastMod, new File("target/scp/remote/out1.txt").lastModified());
        assertFileLength(new File("target/scp/remote/dir/out2.txt"), data.length(), 5000);
        assertEquals(lastMod, new File("target/scp/remote/dir/out2.txt").lastModified());

        Utils.deleteRecursive(new File("target/scp/local"));
        new File("target/scp/local").mkdirs();
        scp.download("target/scp/remote/*", "target/scp/local", ScpClient.Option.Recursive, ScpClient.Option.PreserveAttributes);
        assertFileLength(new File("target/scp/local/out1.txt"), data.length(), 5000);
        assertEquals(lastMod, new File("target/scp/local/out1.txt").lastModified());
        assertFileLength(new File("target/scp/local/dir/out2.txt"), data.length(), 5000);
        assertEquals(lastMod, new File("target/scp/local/dir/out2.txt").lastModified());

        session.close(false).await();
        client.stop();
    }

    private void writeFile(File file, String data) throws IOException {
        FileOutputStream fos = new FileOutputStream(file);
        try {
            fos.write(data.getBytes());
        } finally {
            fos.close();
        }
    }

    @Test
    public void testScp() throws Exception {
        session = getJschSession();

        String data = "0123456789\n";

        String unixDir = "target/scp";
        String fileName = "out.txt";
        String unixPath = unixDir + File.separator + fileName;
        File root = new File(unixDir);
        File target = new File(unixPath);
        Utils.deleteRecursive(root);
        root.mkdirs();
        assertTrue(root.exists());

        target.delete();
        assertFalse(target.exists());
        sendFile(unixPath, "out.txt", data);
        assertFileLength(target, data.length(), 5000);

        target.delete();
        assertFalse(target.exists());
        sendFile(unixDir, "out.txt", data);
        assertFileLength(target, data.length(), 5000);

        sendFileError("target", "scp", "0123456789\n");

        readFileError(unixDir);

        assertEquals(data, readFile(unixPath));

        assertEquals(data, readDir(unixDir));

        target.delete();
        root.delete();

        sendDir("target", "scp", "out.txt", data);
        assertFileLength(target, data.length(), 5000);
    }

    @Test
    public void testWithGanymede() throws Exception {
        // begin client config
        final Connection conn = new Connection("localhost", port);
        conn.connect(null, 5000, 0);
        conn.authenticateWithPassword("sshd", "sshd");
        final SCPClient scp_client = new SCPClient(conn);
        final Properties props = new Properties();
        props.setProperty("test", "test-passed");
        File f = new File("target/scp/gan");
        Utils.deleteRecursive(f);
        f.mkdirs();
        assertTrue(f.exists());

        String name = "test.properties";
        scp_client.put(toBytes(props, ""), name, "target/scp/gan");
        assertTrue(new File(f, name).exists());
        assertTrue(new File(f, name).delete());

        name = "test2.properties";
        scp_client.put(toBytes(props, ""), name, "target/scp/gan");
        assertTrue(new File(f, name).exists());
        assertTrue(new File(f, name).delete());

        assertTrue(f.delete());
        conn.close();
    }

    private byte[] toBytes(final Properties properties, final String comments) {
        try {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            properties.store(baos, comments);
            baos.close();
            return baos.toByteArray();
        } catch (final IOException cause) {
            throw new RuntimeException("Failed to output properties to byte[]", cause);
        }
    }

    protected void assertFileLength(File file, long length, long timeout) throws Exception{
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
        ChannelExec c = (ChannelExec) session.openChannel("exec");
        OutputStream os = c.getOutputStream();
        InputStream is = c.getInputStream();
        c.setCommand("scp -f " + path);
        c.connect();
        os.write(0);
        os.flush();
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
        OutputStream os = c.getOutputStream();
        InputStream is = c.getInputStream();
        c.setCommand("scp -r -f " + path);
        c.connect();
        os.write(0);
        os.flush();
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
        os.write(0);
        os.flush();

        c.disconnect();
        return new String(buffer);
    }

    protected String readFileError(String path) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel("exec");
        OutputStream os = c.getOutputStream();
        InputStream is = c.getInputStream();
        c.setCommand("scp -f " + path);
        c.connect();
        os.write(0);
        os.flush();
        assertEquals(2, is.read());
        c.disconnect();
        return null;
    }

    protected void sendFile(String path, String name, String data) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel("exec");
        c.setCommand("scp -t " + path);
        OutputStream os = c.getOutputStream();
        InputStream is = c.getInputStream();
        c.connect();
        assertEquals(0, is.read());
        os.write(("C7777 "+ data.length() + " " + name + "\n").getBytes());
        os.flush();
        assertEquals(0, is.read());
        os.write(data.getBytes());
        os.flush();
        assertEquals(0, is.read());
        os.write(0);
        os.flush();
        Thread.sleep(100);
        c.disconnect();
    }

    protected void sendFileError(String path, String name, String data) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel("exec");
        OutputStream os = c.getOutputStream();
        InputStream is = c.getInputStream();
        c.setCommand("scp -t " + path);
        c.connect();
        assertEquals(0, is.read());
        os.write(("C7777 "+ data.length() + " " + name + "\n").getBytes());
        os.flush();
        assertEquals(2, is.read());
        c.disconnect();
    }

    protected void sendDir(String path, String dirName, String fileName, String data) throws Exception {
        ChannelExec c = (ChannelExec) session.openChannel("exec");
        OutputStream os = c.getOutputStream();
        InputStream is = c.getInputStream();
        c.setCommand("scp -t -r " + path);
        c.connect();
        assertEquals(0, is.read());
        os.write(("D0755 0 " + dirName + "\n").getBytes());
        os.flush();
        assertEquals(0, is.read());
        os.write(("C7777 " + data.length() + " " + fileName + "\n").getBytes());
        os.flush();
        assertEquals(0, is.read());
        os.write(data.getBytes());
        os.flush();
        assertEquals(0, is.read());
        os.write(0);
        os.flush();
        os.write("E\n".getBytes());
        os.flush();
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
