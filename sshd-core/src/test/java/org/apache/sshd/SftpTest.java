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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Vector;

import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.SftpException;
import org.apache.sshd.client.SftpClient;
import org.apache.sshd.client.sftp.DefaultSftpClient;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.server.sftp.SftpSubsystem;
import org.apache.sshd.util.BaseTest;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.JSchLogger;
import org.apache.sshd.util.SimpleUserInfo;
import org.apache.sshd.util.Utils;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.*;

public class SftpTest extends BaseTest {

    private SshServer sshd;
    private int port;
    private com.jcraft.jsch.Session session;

    @Before
    public void setUp() throws Exception {
        sshd = SshServer.setUpDefaultServer();
        sshd.setKeyPairProvider(Utils.createTestHostKeyProvider());
        sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystem.Factory()));
        sshd.setCommandFactory(new ScpCommandFactory());
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.start();
        port = sshd.getPort();

        JSchLogger.init();
        JSch sch = new JSch();
        session = sch.getSession("sshd", "localhost", port);
        session.setUserInfo(new SimpleUserInfo("sshd"));
        session.connect();
    }

    @After
    public void tearDown() throws Exception {
        session.disconnect();
        sshd.stop(true);
    }

    @Test
    @Ignore
    public void testExternal() throws Exception {
        System.out.println("SFTP subsystem available on port " + port);
        Thread.sleep(5 * 60000);
    }

    @Test
    public void testOpen() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("x", "localhost", port).await().getSession();
        session.addPasswordIdentity("x");
        session.auth().verify();

        String file = "target/sftp/client/testOpen.txt";
        File javaFile = new File(file);

        javaFile.getParentFile().mkdirs();
        javaFile.createNewFile();
        javaFile.setWritable(false, false);
        javaFile.setReadable(false, false);

        SftpClient sftp = session.createSftpClient();
        SftpClient.Handle h;

        boolean	isWindows = OsUtils.isWin32();

        try {
            h = sftp.open(file, EnumSet.of(SftpClient.OpenMode.Read));
            // NOTE: on Windows files are always readable
            // see https://svn.apache.org/repos/asf/harmony/enhanced/java/branches/java6/classlib/modules/luni/src/test/api/windows/org/apache/harmony/luni/tests/java/io/WinFileTest.java
            Assert.assertTrue("Empty read should have failed", isWindows);
            sftp.close(h);
        } catch (IOException e) {
            if (isWindows) {
                throw e;
            }
        }

        try {
            h = sftp.open(file, EnumSet.of(SftpClient.OpenMode.Write));
            fail("Empty write should have failed");
        } catch (IOException e) {
            // ok
        }

        try {
            h = sftp.open(file, EnumSet.of(SftpClient.OpenMode.Truncate));
            fail("Empty truncate should have failed");
        } catch (IOException e) {
            // ok
        }

        // NOTE: on Windows files are always readable
        int	perms=sftp.stat(file).perms;
        int	permsMask=SftpClient.S_IWUSR | (isWindows ? 0 : SftpClient.S_IRUSR);
        Assert.assertEquals("Mismatched permissions - 0x" + Integer.toHexString(perms), 0, (perms & permsMask));

        javaFile.setWritable(true, false);

        h = sftp.open(file, EnumSet.of(SftpClient.OpenMode.Truncate, SftpClient.OpenMode.Write));
        sftp.close(h);

        h = sftp.open(file, EnumSet.of(SftpClient.OpenMode.Write));
        byte[] d = "0123456789\n".getBytes();
        sftp.write(h, 0, d, 0, d.length);
        sftp.write(h, d.length, d, 0, d.length);
        sftp.close(h);
        h = sftp.open(file, EnumSet.of(SftpClient.OpenMode.Write));
        sftp.write(h, d.length * 2, d, 0, d.length);
        sftp.close(h);
        h = sftp.open(file, EnumSet.of(SftpClient.OpenMode.Write));
        sftp.write(h, 3, "-".getBytes(), 0, 1);
        sftp.close(h);

        try {
            h = sftp.open(file, EnumSet.of(SftpClient.OpenMode.Read));
            // NOTE: on Windows files are always readable
            Assert.assertTrue("Data read should have failed", isWindows);
            sftp.close(h);
        } catch (IOException e) {
            if (isWindows) {
                throw e;
            }
        }

        javaFile.setReadable(true, false);

        h = sftp.open(file, EnumSet.of(SftpClient.OpenMode.Read));
        byte[] buf = new byte[3];
        int l = sftp.read(h, 2l, buf, 0, 3);
        assertEquals("Mismatched read data", "2-4", new String(buf, 0, l));
        sftp.close(h);
    }

    @Test
    public void testClient() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("x", "localhost", port).await().getSession();
        session.addPasswordIdentity("x");
        session.auth().verify();

        Utils.deleteRecursive(new File("target/sftp"));
        new File("target/sftp").mkdirs();
        new File("target/sftp/client/test.txt").delete();
        new File("target/sftp/client").delete();

        try(SftpClient sftp = session.createSftpClient()) {
            sftp.mkdir("target/sftp/client");
    
            SftpClient.Handle h = sftp.open("target/sftp/client/test.txt", EnumSet.of(SftpClient.OpenMode.Write, SftpClient.OpenMode.Create));
            byte[] d = "0123456789\n".getBytes();
            sftp.write(h, 0, d, 0, d.length);
            sftp.write(h, d.length, d, 0, d.length);
    
            SftpClient.Attributes attrs = sftp.stat(h);
            assertNotNull("No handle attributes", attrs);
    
            sftp.close(h);
    
            h = sftp.openDir("target/sftp/client");
            SftpClient.DirEntry[] dir = sftp.readDir(h);
            assertNotNull("No dir entries", dir);
            assertEquals("Mismatced number of dir entries", 1, dir.length);
            assertNull("Unexpected entry read", sftp.readDir(h));
            sftp.close(h);
    
            sftp.remove("target/sftp/client/test.txt");
    
            byte[]  workBuf=new byte[1024 * 128];
            try(OutputStream os = sftp.write("target/sftp/client/test.txt")) {
                os.write(workBuf);
            }
    
            try(InputStream is = sftp.read("target/sftp/client/test.txt")) {
                int readLen=is.read(workBuf);
                assertEquals("Mismatched read data length", workBuf.length, readLen);

                int i = is.read();
                assertEquals("Unexpected read past EOF", -1, i);
            }

            SftpClient.Attributes attributes = sftp.stat("target/sftp/client/test.txt");
            assertTrue("Test file not detected as regular", attributes.isRegularFile());
    
            attributes = sftp.stat("target/sftp/client");
            assertTrue("Test directory not reported as such", attributes.isDirectory());
    
            int nb = 0;
            for (SftpClient.DirEntry entry : sftp.readDir("target/sftp/client")) {
                assertNotNull("Unexpected null entry", entry);
                nb++;
            }
            assertEquals("Mismatched read dir entries", 1, nb);
    
            sftp.remove("target/sftp/client/test.txt");
    
            sftp.rmdir("target/sftp/client/");
        }

        client.stop();
    }

    /**
     * this test is meant to test out write's logic, to ensure that internal chunking (based on Buffer.MAX_LEN) is
     * functioning properly. To do this, we write a variety of file sizes, both smaller and larger than Buffer.MAX_LEN.
     * in addition, this test ensures that improper arguments passed in get caught with an IllegalArgumentException
     * @throws Exception upon any uncaught exception or failure
     */
    @Test
    public void testWriteChunking() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("x", "localhost", port).await().getSession();
        session.addPasswordIdentity("x");
        session.auth().verify();

        Utils.deleteRecursive(new File("target/sftp"));
        new File("target/sftp").mkdirs();
        new File("target/sftp/client").delete();

        SftpClient sftp = session.createSftpClient();

        sftp.mkdir("target/sftp/client");

        uploadAndVerifyFile(sftp, 0, "emptyFile.txt");
        uploadAndVerifyFile(sftp, 1000, "smallFile.txt");
        uploadAndVerifyFile(sftp, Buffer.MAX_LEN - 1, "bufferMaxLenMinusOneFile.txt");
        uploadAndVerifyFile(sftp, Buffer.MAX_LEN, "bufferMaxLenFile.txt");
        // were chunking not implemented, these would fail. these sizes should invoke our internal chunking mechanism
        uploadAndVerifyFile(sftp, Buffer.MAX_LEN + 1, "bufferMaxLenPlusOneFile.txt");
        uploadAndVerifyFile(sftp, (int)(1.5 * Buffer.MAX_LEN), "1point5BufferMaxLenFile.txt");
        uploadAndVerifyFile(sftp, (2 * Buffer.MAX_LEN) - 1, "2TimesBufferMaxLenMinusOneFile.txt");
        uploadAndVerifyFile(sftp, 2 * Buffer.MAX_LEN, "2TimesBufferMaxLenFile.txt");
        uploadAndVerifyFile(sftp, (2 * Buffer.MAX_LEN) + 1, "2TimesBufferMaxLenPlusOneFile.txt");
        uploadAndVerifyFile(sftp, 200000, "largerFile.txt");

        // test erroneous calls that check for negative values
        testInvalidParams(sftp);

        // cleanup
        sftp.rmdir("target/sftp/client");
        sftp.close();
        client.stop();
    }

    private void testInvalidParams(SftpClient sftp) throws Exception {
        // generate random file and upload it
        final String filePath = "target/sftp/client/invalid";
        SftpClient.Handle handle = sftp.open(filePath, EnumSet.of(SftpClient.OpenMode.Write, SftpClient.OpenMode.Create));
        String randomData = randomString(5);
        try {
            sftp.write(handle, -1, randomData.getBytes(), 0, 0);
            fail("should not have been able to write file with invalid file offset");
        } catch (IllegalArgumentException e) {
            // expected
        }
        try {
            sftp.write(handle, 0, randomData.getBytes(), -1, 0);
            fail("should not have been able to write file with invalid source offset");
        } catch (IllegalArgumentException e) {
            // expected
        }
        try {
            sftp.write(handle, 0, randomData.getBytes(), 0, -1);
            fail("should not have been able to write file with invalid length");
        } catch (IllegalArgumentException e) {
            // expected
        }
        try {
            sftp.write(handle, 0, randomData.getBytes(), 0, randomData.length() + 1);
            fail("should not have been able to write file with length bigger than array itself (no offset)");
        } catch (IllegalArgumentException e) {
            // expected
        }
        try {
            sftp.write(handle, 0, randomData.getBytes(), randomData.length(), 1);
            fail("should not have been able to write file with length bigger than array itself (with offset)");
        } catch (IllegalArgumentException e) {
            // expected
        }

        // cleanup
        sftp.close(handle);
        sftp.remove(filePath);
        assertFalse("file should not be there", new File(filePath).exists());
    }

    private void uploadAndVerifyFile(SftpClient sftp, int size, String filename) throws Exception {
        // generate random file and upload it
        final String filePath = "target/sftp/client/" + filename;
        SftpClient.Handle handle = sftp.open(filePath, EnumSet.of(SftpClient.OpenMode.Write, SftpClient.OpenMode.Create));
        String randomData = randomString(size);
        sftp.write(handle, 0, randomData.getBytes(), 0, randomData.length());
        sftp.close(handle);

        // verify results
        File resultFile = new File(filePath);
        assertTrue("file should exist on disk", resultFile.exists());
        assertTrue("file contents should match", randomData.equals(readFile(filePath)));

        // cleanup
        sftp.remove(filePath);
        assertFalse("file should have been removed", resultFile.exists());
    }

    @Test
    public void testSftp() throws Exception {
        String d = "0123456789\n";

        File root = new File("target/sftp");
        File target = new File("target/sftp/out.txt");
        Utils.deleteRecursive(root);
        root.mkdirs();
        assertTrue(root.exists());

        for (int j = 10; j <= 10; j++) {
            String data = "";
            for (int i = 0; i < j; i++) {
                data = data + d;
            }

            target.delete();
            assertFalse(target.exists());
            sendFile("target/sftp/out.txt", data);
            assertFileLength(target, data.length(), 5000);

            target.delete();
            assertFalse(target.exists());
        }
        root.delete();
    }

    @Test
    public void testReadWriteWithOffset() throws Exception {
        File root = new File("target/sftp");
        Utils.deleteRecursive(root);
        assertHierarchyTargetFolderExists(root);

        String unixPath = "target/sftp/out.txt";
        File target = new File(unixPath);

        ChannelSftp c = (ChannelSftp) session.openChannel("sftp");
        c.connect();
        c.put(new ByteArrayInputStream("0123456789".getBytes()), unixPath);

        assertTrue("Target not created after initial write: " + target.getAbsolutePath(), target.exists());
        assertEquals("0123456789", readFile(unixPath));

        try(OutputStream os = c.put(unixPath, null, ChannelSftp.APPEND, -5)) {
            os.write("a".getBytes());
        }
        c.disconnect();

        assertTrue("Target not created after data update: " + target.getAbsolutePath(), target.exists());
        assertEquals("Mismatched file data", "01234a6789", readFile(unixPath));

        assertTrue("Failed to delete " + target.getAbsolutePath(), target.delete());
        assertFalse("Target not deleted: " + target.getAbsolutePath(), target.exists());
        root.delete();
    }

    @Test
    public void testReadDir() throws Exception {
        ChannelSftp c = (ChannelSftp) session.openChannel("sftp");
        c.connect();

        URI url = getClass().getClassLoader().getResource(SshClient.class.getName().replace('.', '/') + ".class").toURI();
        URI base = new File(System.getProperty("user.dir")).getAbsoluteFile().toURI();
        String path = new File(base.relativize(url).getPath()).getParent() + "/";
        path = path.replace('\\', '/');
        Vector res = c.ls(path);
        for (Object f : res) {
            System.out.println(f.toString());
        }
    }

    @Test
    public void testRealPath() throws Exception {
        ChannelSftp c = (ChannelSftp) session.openChannel("sftp");
        c.connect();

        URI url = getClass().getClassLoader().getResource(SshClient.class.getName().replace('.', '/') + ".class").toURI();
        URI base = new File(System.getProperty("user.dir")).getAbsoluteFile().toURI();
        String path = new File(base.relativize(url).getPath()).getParent() + "/";
        path = path.replace('\\', '/');
        String real = c.realpath(path);
        System.out.println(real);
        try {
            real = c.realpath(path + "/foobar");
            System.out.println(real);
            fail("Expected SftpException");
        } catch (SftpException e) {
            // ok
        }
    }

    @Test
    public void testRename() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("x", "localhost", port).await().getSession();
        session.addPasswordIdentity("x");
        session.auth().verify();

        Utils.deleteRecursive(new File("target/sftp"));
        new File("target/sftp").mkdirs();
        new File("target/sftp/client").delete();

        SftpClient sftp = session.createSftpClient();
        try (OutputStream os = sftp.write("target/sftp/test.txt")) {
            os.write("Hello world!\n".getBytes());
        }

        try {
            sftp.rename("target/sftp/test2.txt", "target/sftp/test3.txt");
            fail("Expected an SftpException");
        } catch (org.apache.sshd.client.SftpException e) {
            assertEquals(DefaultSftpClient.SSH_FX_NO_SUCH_FILE, e.getStatus());
        }

        try (OutputStream os = sftp.write("target/sftp/test2.txt")) {
            os.write("H".getBytes());
        }

        try {
            sftp.rename("target/sftp/test.txt", "target/sftp/test2.txt");
            fail("Expected an SftpException");
        } catch (org.apache.sshd.client.SftpException e) {
            assertEquals(DefaultSftpClient.SSH_FX_FILE_ALREADY_EXISTS, e.getStatus());
        }
        sftp.rename("target/sftp/test.txt", "target/sftp/test2.txt", SftpClient.CopyMode.Overwrite);
    }

    @Test
    public void testCreateSymbolicLink() throws Exception {
        // Do not execute on windows as the file system does not support symlinks
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            return;
        }

        File root = new File("target/sftp");
        String unixPath = "target/sftp/out.txt";
        String linkUnixPath = "target/sftp/link.txt";
        File target = new File(unixPath);
        File link = new File(linkUnixPath);
        Utils.deleteRecursive(root);
        root.mkdirs();
        assertTrue(root.exists());

        ChannelSftp c = (ChannelSftp) session.openChannel("sftp");
        c.connect();
        c.put(new ByteArrayInputStream("0123456789".getBytes()), unixPath);

        assertTrue(target.exists());
        assertEquals("0123456789", readFile(unixPath));

        c.symlink(unixPath, linkUnixPath);

        assertTrue(link.exists());
        assertEquals("0123456789", readFile(linkUnixPath));

        String str1 = c.readlink(linkUnixPath);
        String str2 = c.realpath(unixPath);
        assertEquals(str1, str2);
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

    private String randomString(int size) {
        StringBuilder sb = new StringBuilder(size);
        for (int i = 0; i < size; i++) {
            sb.append((char) ((i % 10) + '0'));
        }
        return sb.toString();
    }

}
