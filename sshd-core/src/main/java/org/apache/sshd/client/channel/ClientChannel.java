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
import org.apache.sshd.common.SshConstants;
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
     * Obtains an {@link OutputStream} to send data directly to the remote end of the channel. This can be used instead
     * of using {@link #setIn(InputStream)} method and having the channel polling for data in that stream.
     * <p>
     * When the channel closes, it will {@link OutputStream#close() close} the returned stream.
     * </p>
     * <p>
     * This method should be called only after the channel has been opened.
     * </p>
     *
     * @return an {@link OutputStream} for sending data, or {@code null} if an input stream was set via
     *         {@link #setIn(InputStream)}
     * @see    #setIn(InputStream)
     */
    OutputStream getInvertedIn();

    /**
     * Obtains an {@link InputStream} to read received {@link SshConstants#SSH_MSG_CHANNEL_DATA} data directly from the
     * channel. This is an alternative to {@link #setOut(OutputStream)}. If the error stream is redirected to the output
     * stream via {@link #setRedirectErrorStream(boolean) setRedirectErrorStream(true)}, this stream will also receive
     * {@link SshConstants#SSH_MSG_CHANNEL_EXTENDED_DATA} data.
     * <p>
     * When the channel closes, it will <em>not</em> close the returned stream. It is the caller's responsibility to
     * close the returned stream if needed. Closing the stream while the channel is open may cause the channel to be
     * closed forcibly if more data arrives. The stream remains open after the channel has closed, so that the caller
     * can read the last arrived data even afterwards.
     * </p>
     * <p>
     * As with all external processes, the application should read this stream to avoid that the channel blocks when the
     * stream's buffer is full. The buffer size for the returned stream is bounded by the channel's local window size.
     * If the caller does not read this stream, the channel will block once the local window is exhausted.
     * </p>
     * <p>
     * This method should be called only after the channel has been opened.
     * </p>
     *
     * @return an {@link InputStream} for reading received data, or {@code null} if an output stream was set via
     *         {@link #setOut(OutputStream)}
     * @see    #setOut(OutputStream)
     * @see    #setRedirectErrorStream(boolean)
     */
    InputStream getInvertedOut();

    /**
     * Obtains an {@link InputStream} to read received {@link SshConstants#SSH_MSG_CHANNEL_EXTENDED_DATA} data directly
     * from the channel. This is an alternative to {@link #setErr(OutputStream)}. If the error stream is redirected to
     * the output stream via {@link #setRedirectErrorStream(boolean) setRedirectErrorStream(true)}, the returned stream
     * will not receive any data and be always at EOF.
     * <p>
     * When the channel closes, it will <em>not</em> close the returned stream. It is the caller's responsibility to
     * close the returned stream if needed. Closing the stream while the channel is open may cause the channel to be
     * closed forcibly if more data arrives. The stream remains open after the channel has closed, so that the caller
     * can read the last arrived data even afterwards.
     * </p>
     * <p>
     * As with all external processes, the application should read this stream (unless it was redirected) to avoid that
     * the channel blocks when the stream's buffer is full. The buffer size for the returned stream is bounded by the
     * channel's local window size. If the caller does not read this stream, the channel will block once the local
     * window is exhausted.
     * </p>
     * <p>
     * This method should be called only after the channel has been opened.
     * </p>
     *
     * @return an {@link InputStream} for reading received data, or {@code null} if an output stream was set via
     *         {@link #setErr(OutputStream)}
     * @see    #setErr(OutputStream)
     * @see    #setRedirectErrorStream(boolean)
     */
    InputStream getInvertedErr();

    /**
     * Sets an {@link InputStream} that will be read by this channel and forwarded to the remote channel. Note that
     * using such a stream will create an additional thread for pumping the stream which will only be able to end when
     * that stream is actually closed or EOF on the stream is reached. It is recommended to use the
     * {@link #getInvertedIn()} method instead and write data directly.
     * <p>
     * The stream must be set before the channel is opened. When the channel closes, it will {@link InputStream#close()
     * close} the given stream.
     * </p>
     *
     * @param in an {@link InputStream} to be polled and forwarded
     * @see      #getInvertedIn()
     */
    void setIn(InputStream in);

    /**
     * Sets an output stream for the channel to write received {@link SshConstants#SSH_MSG_CHANNEL_DATA} data to. For
     * remote command execution, this is typically the remote command's {@code stdout}. If the error stream is
     * redirected to the output stream via {@link #setRedirectErrorStream(boolean) setRedirectErrorStream(true)}, this
     * stream will also receive {@link SshConstants#SSH_MSG_CHANNEL_EXTENDED_DATA} data.
     * <p>
     * The stream must be set before the channel is opened. When the channel closes, it will {@link OutputStream#close()
     * close} the given stream.
     * </p>
     * <p>
     * If no stream is set by the time the channel is opened, the channel will internally forward data to a stream that
     * can be read via the {@link InputStream} obtained via {@link #getInvertedOut()}.
     * </p>
     *
     * @param out the {@link OutputStream}
     * @see       #getInvertedOut()
     * @see       #setRedirectErrorStream(boolean)
     */
    void setOut(OutputStream out);

    /**
     * Sets an output stream for the channel to write received {@link SshConstants#SSH_MSG_CHANNEL_EXTENDED_DATA} data
     * to. For remote command execution, this is typically the remote command's {@code stderr}.
     * <p>
     * The stream must be set before the channel is opened. When the channel closes, it will {@link OutputStream#close()
     * close} the given stream.
     * </p>
     * <p>
     * If no stream is set by the time the channel is opened, the channel will internally forward data to a stream that
     * can be read via the {@link InputStream} obtained via {@link #getInvertedErr()}. (Or it might forward the data to
     * the output stream if {@link #setRedirectErrorStream(boolean) setRedirectErrorStream(true)} is set.)
     * </p>
     *
     * @param err the {@link OutputStream}
     * @see       #getInvertedErr()
     * @see       #setRedirectErrorStream(boolean)
     */
    void setErr(OutputStream err);

    /**
     * Defines whether to redirect the error stream into the output stream; has no effect if
     * {@link #setErr(OutputStream)} has also been called by the time the channel is opened.
     *
     * @param redirectErrorStream whether to redirect the error stream to the output stream.
     */
    void setRedirectErrorStream(boolean redirectErrorStream);

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
            throw new RemoteException("Remote command failed (" + exitStatus + "): " + command,
                    new ServerException(exitStatus.toString()));
        }
    }

}
