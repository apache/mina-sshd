/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.util.test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.jcraft.jsch.Session;

/**
 * Helper methods to work around bugs in JSch, which is used in tests.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class JSchUtils {

    private JSchUtils() {
        throw new UnsupportedOperationException("Instantiation not allowed");
    }

    @FunctionalInterface
    private interface Request {
        void run() throws Exception;
    }

    private static void wrappedGlobalRequest(Request request) throws Exception {
        // JSch has a serious bug here. It uses a spin loop to wait for the reply for a global request,
        // and when the reply arrives in its read thread, it interrupts the presumably spinning thread (i.e., *this*
        // thread). But due to a race condition, this thread may have actually already gotten the result and
        // returned from the call, and will be interrupted later.
        //
        // The work-around is to make the request in a separate thread and wait on it.
        Exception[] inner = { null };
        CountDownLatch forwardingEstablished = new CountDownLatch(1);
        Thread forwardingOpener = new Thread(() -> {
            try {
                request.run();
            } catch (Exception e) {
                inner[0] = e;
            } finally {
                forwardingEstablished.countDown();
            }
        });
        forwardingOpener.start();
        if (!forwardingEstablished.await(5, TimeUnit.SECONDS)) {
            throw new TimeoutException("Port forwarding not established with 5 seconds");
        }
        if (inner[0] != null) {
            throw inner[0];
        }
    }

    /**
     * Wraps {@link Session#setPortForwardingR(String, int, String, int)} to avoid that JSch's abuse of
     * {@link Thread#interrupt()} leaks into client code.
     *
     * @param  session    JSch {@link Session} to request the port forwarding on
     * @param  remotePort the remote port to forward
     * @param  host       the host to forward to
     * @param  port       the port on {@code host} to forward to
     * @throws Exception  if the port forwarding cannot be established
     */
    public static void setRemotePortForwarding(Session session, int remotePort, String host, int port) throws Exception {
        wrappedGlobalRequest(() -> session.setPortForwardingR(remotePort, host, port));
    }

    /**
     * Wraps {@link Session#setPortForwardingR(int, String, int)} to avoid that JSch's abuse of
     * {@link Thread#interrupt()} leaks into client code.
     *
     * @param  session     JSch {@link Session} to request the port forwarding on
     * @param  bindAddress the bind address for listening
     * @param  remotePort  the remote port to forward
     * @param  host        the host to forward to
     * @param  port        the port on {@code host} to forward to
     * @throws Exception   if the port forwarding cannot be established
     */
    public static void setRemotePortForwarding(Session session, String bindAddress, int remotePort, String host, int port)
            throws Exception {
        wrappedGlobalRequest(() -> session.setPortForwardingR(bindAddress, remotePort, host, port));
    }
}
