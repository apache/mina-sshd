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
package org.apache.sshd.client.channel;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.rmi.RemoteException;
import java.rmi.ServerException;
import java.time.Duration;
import java.util.Collection;
import java.util.Set;

import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionHolder;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.StreamingChannel;
import org.apache.sshd.common.io.IoInputStream;
import org.apache.sshd.common.io.IoOutputStream;

/**
 * A client channel used to communicate with the SSH server. Client channels can be shells, simple commands or
 * subsystems. <B>Note:</B> client channels may be associated with a <U>server</U> session if they are opened by the
 * server - e.g., for agent proxy, port forwarding, etc..
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ClientChannel extends Channel, StreamingChannel, ClientSessionHolder {

    @Override
    default ClientSession getClientSession() {
        return (ClientSession) getSession();
    }

    /**
     * @return The type of channel reported when it was created
     */
    String getChannelType();

    IoOutputStream getAsyncIn();

    IoInputStream getAsyncOut();

    IoInputStream getAsyncErr();

    /**
     * Access to an output stream to send data directly to the remote channel. This can be used instead of using
     * {@link #setIn(java.io.InputStream)} method and having the channel polling for data in that stream.
     *
     * @return an OutputStream to be used to send data
     */
    OutputStream getInvertedIn();

    InputStream getInvertedOut();

    InputStream getInvertedErr();

    /**
     * Set an input stream that will be read by this channel and forwarded to the remote channel. Note that using such a
     * stream will create an additional thread for pumping the stream which will only be able to end when that stream is
     * actually closed or some data is read. It is recommended to use the {@link #getInvertedIn()} method instead and
     * write data directly.
     *
     * @param in an InputStream to be polled and forwarded
     */
    void setIn(InputStream in);

    void setOut(OutputStream out);

    void setErr(OutputStream err);

    OpenFuture open() throws IOException;

    /**
     * @return A snapshot of the current channel state
     * @see    #waitFor(Collection, long)
     */
    Set<ClientChannelEvent> getChannelState();

    /**
     * Waits until any of the specified events in the mask is signaled
     *
     * @param  mask    The {@link ClientChannelEvent}s mask
     * @param  timeout The timeout to wait (msec.) - if non-positive then forever
     * @return         The actual signaled event - includes {@link ClientChannelEvent#TIMEOUT} if timeout expired before
     *                 the expected event was signaled
     */
    Set<ClientChannelEvent> waitFor(Collection<ClientChannelEvent> mask, long timeout);

    /**
     * Waits until any of the specified events in the mask is signaled
     *
     * @param  mask    The {@link ClientChannelEvent}s mask
     * @param  timeout The timeout to wait - if null then forever
     * @return         The actual signaled event - includes {@link ClientChannelEvent#TIMEOUT} if timeout expired before
     *                 the expected event was signaled
     */
    default Set<ClientChannelEvent> waitFor(Collection<ClientChannelEvent> mask, Duration timeout) {
        return waitFor(mask, timeout != null ? timeout.toMillis() : -1);
    }

    /**
     * @return The signaled exit status via &quot;exit-status&quot; request - {@code null} if not signaled
     */
    Integer getExitStatus();

    /**
     * @return The signaled exit signal via &quot;exit-signal&quot; - {@code null} if not signaled
     */
    String getExitSignal();

    /**
     * Makes sure remote command exit status has been provided and it is zero
     *
     * @param  command         The command string - used only for exception text
     * @param  exitStatus      The exit status value
     * @throws RemoteException If <tt>exitStatus</tt> is {@code null} or non-zero
     */
    static void validateCommandExitStatusCode(String command, Integer exitStatus) throws RemoteException {
        if (exitStatus == null) {
            throw new RemoteException("No exit status returned for command=" + command);
        }
        if (exitStatus.intValue() != 0) {
            throw new RemoteException(
                    "Remote command failed (" + exitStatus + "): " + command, new ServerException(exitStatus.toString()));
        }
    }

}
