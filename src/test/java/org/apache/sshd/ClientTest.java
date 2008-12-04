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

import java.io.PipedOutputStream;
import java.io.PipedInputStream;
import java.io.ByteArrayOutputStream;
import java.net.ServerSocket;

import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.util.BufferUtils;
import org.apache.sshd.ClientChannel;
import org.apache.sshd.ClientSession;
import org.apache.sshd.SshClient;
import org.apache.sshd.SshServer;
import org.apache.sshd.util.EchoShellFactory;
import org.apache.sshd.util.BogusPasswordAuthenticator;
import org.apache.sshd.util.TeePipedOutputStream;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class ClientTest {

    private SshServer sshd;
    private int port;

    @Before
    public void setUp() throws Exception {
        ServerSocket s = new ServerSocket(0);
        port = s.getLocalPort();
        s.close();

        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.setKeyPairProvider(new FileKeyPairProvider(new String[] { "src/test/resources/hostkey.pem" }));
        sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.start();
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop();
            Thread.sleep(50);
        }
    }

    @Test
    public void testClient() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();
        ClientSession session = client.connect("localhost", port);
        session.authPassword("smx", "smx");
        ClientChannel channel = session.createChannel("shell");
        ByteArrayOutputStream sent = new ByteArrayOutputStream();
        PipedOutputStream pipedIn = new TeePipedOutputStream(sent);
        channel.setIn(new PipedInputStream(pipedIn));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        channel.setOut(out);
        channel.setErr(err);
        channel.open();

        pipedIn.write("this is my command\n".getBytes());
        pipedIn.flush();

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            sb.append("0123456789");
        }
        sb.append("\n");
        pipedIn.write(sb.toString().getBytes());

        pipedIn.write("exit\n".getBytes());
        pipedIn.flush();

        channel.waitFor(ClientChannel.CLOSED, 0);

        channel.close();
        client.stop();

        assertArrayEquals(sent.toByteArray(), out.toByteArray());
    }

    @Test
    public void testClientWithLengthyDialog() throws Exception {
        SshClient client = SshClient.setUpDefaultClient();
        // Reduce window size and packet size
//        client.getProperties().put(SshClient.WINDOW_SIZE, Integer.toString(0x20000));
//        client.getProperties().put(SshClient.MAX_PACKET_SIZE, Integer.toString(0x1000));
//        sshd.getProperties().put(SshServer.WINDOW_SIZE, Integer.toString(0x20000));
//        sshd.getProperties().put(SshServer.MAX_PACKET_SIZE, Integer.toString(0x1000));
        client.start();
        ClientSession session = client.connect("localhost", port);
        session.authPassword("smx", "smx");
        ClientChannel channel = session.createChannel("shell");
        ByteArrayOutputStream sent = new ByteArrayOutputStream();
        PipedOutputStream pipedIn = new TeePipedOutputStream(sent);
        channel.setIn(new PipedInputStream(pipedIn));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        channel.setOut(out);
        channel.setErr(err);
        channel.open();

        long t0 = System.currentTimeMillis();

        int bytes = 0;
        for (int i = 0; i < 100000; i++) {
            byte[] data = "01234567890123456789012345678901234567890123456789\n".getBytes();
            pipedIn.write(data);
            pipedIn.flush();
            bytes += data.length;
            if ((bytes & 0xFFF00000) != ((bytes - data.length) & 0xFFF00000)) {
                System.out.println("Bytes written: " + bytes);
            }
        }
        pipedIn.write("exit\n".getBytes());
        pipedIn.flush();

        long t1 = System.currentTimeMillis();

        System.out.println("Sent " + (bytes / 1024) + " Kb in " + (t1 - t0) + " ms");

        System.out.println("Waiting for channel to be closed");

        channel.waitFor(ClientChannel.CLOSED, 0);

        channel.close();
        client.stop();

        assertTrue(BufferUtils.equals(sent.toByteArray(), out.toByteArray()));
        //assertArrayEquals(sent.toByteArray(), out.toByteArray());
    }

    public static void main(String[] args) throws Exception {
        SshClient.main(args);
    }
}
