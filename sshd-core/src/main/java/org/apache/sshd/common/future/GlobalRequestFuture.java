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
package org.apache.sshd.common.future;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * A {@link DefaultSshFuture} that can be used to wait for the reply of an SSH_MSG_GLOBAL_REQUEST sent with
 * {@code want-reply = true}.
 *
 * @see {@link org.apache.sshd.common.session.Session#request(Buffer, String, ReplyHandler)}
 */
public class GlobalRequestFuture extends DefaultSshFuture<GlobalRequestFuture>
        implements SshFutureListener<IoWriteFuture> {

    /**
     * A {@code ReplyHandler} is invoked asynchronously when the reply for a request with {@code want-reply = true} is
     * received. It is <em>not</em> invoked if the request could not be sent; to catch such cases
     * {@link DefaultSshFuture#await()} the {@link GlobalRequestFuture} and check
     * {@link GlobalRequestFuture#getException()}.
     */
    @FunctionalInterface
    public interface ReplyHandler {

        /**
         * Invoked by the framework upon reception of the reply. If the global request was sent with
         * {@code want-reply = false}, it is invoked with {@link SshConstants#SSH_MSG_REQUEST_SUCCESS} and an empty
         * buffer after the request was successfully sent.
         *
         * @param cmd    the command received, can be one of {@link SshConstants#SSH_MSG_REQUEST_SUCCESS},
         *               {@link SshConstants#SSH_MSG_UNIMPLEMENTED}, or {@link SshConstants#SSH_MSG_REQUEST_FAILURE}
         * @param buffer the {@link Buffer} received
         */
        void accept(int cmd, Buffer buffer);
    }

    private final ReplyHandler handler;

    private long sequenceNumber;

    /**
     * Creates a new {@link GlobalRequestFuture} for a global request. Synchronization occurs on the future itself. The
     * future will be fulfilled once the reply has been received or an error occurred.
     *
     * @param request the request identifier
     */
    public GlobalRequestFuture(String request) {
        this(request, null);
    }

    /**
     * Creates a new {@link GlobalRequestFuture} for a global request. Synchronization occurs on the future itself. The
     * future will be fulfilled once the request has been sent, or an error occurred during sending. The framework will
     * invoke the handler once the reply has been received. For global requests with {@code want-reply = false}, the
     * handler will be invoked with an empty buffer if the request was successfully sent.
     *
     * @param request the request identifier
     * @param handler the {@link ReplyHandler}, or {@code null}
     */
    public GlobalRequestFuture(String request, ReplyHandler handler) {
        super(request, null);
        this.handler = handler;
    }

    @Override
    public String getId() {
        return (String) super.getId();
    }

    /**
     * Retrieves this future's packet sequence number.
     *
     * @return the sequence number
     */
    public long getSequenceNumber() {
        return sequenceNumber;
    }

    /**
     * Sets the packet sequence number of the global request represented by this future.
     *
     * @param  number                   the packet sequence number
     * @throws IllegalArgumentException if the number given is not an unsigned 32bit value
     */
    public void setSequenceNumber(long number) {
        if (number < 0 || ((number & 0xFFFF_FFFFL) != number)) {
            throw new IllegalArgumentException("Invalid sequence number " + number);
        }
        sequenceNumber = number;
    }

    /**
     * Fulfills this future, marking it as failed.
     *
     * @param message An explanation of the failure reason
     */
    public void fail(String message) {
        setValue(new SshException(GenericUtils.isEmpty(message) ? "Global request failure; unknown reason" : message));
    }

    /**
     * Retrieves the {@link ReplyHandler} of this future, if any.
     *
     * @return the handler, or {@code null} if none was set
     */
    public ReplyHandler getHandler() {
        return handler;
    }

    /**
     * Obtains the reply {@link Buffer} if the request was successful. If called after {@link #isDone()} is
     * {@code true}, a non-{@code null} result means the request was successful.
     *
     * @return the {@link Buffer}, or {@code null} if the request was not successful or the reply was not received yet
     */
    public Buffer getBuffer() {
        Object value = getValue();
        if (value instanceof Buffer) {
            return (Buffer) value;
        }
        return null;
    }

    /**
     * Retrieves an exception if the request failed. If called after {@link #isDone()} is {@code true}, a
     * {@code null} result means the request did not fail.
     *
     * @return a failure reason, or {@code null} if there isn't one or if the request did not fail
     */
    public Throwable getException() {
        Object value = getValue();
        if (value instanceof Throwable) {
            return (Throwable) value;
        }
        return null;
    }

    @Override
    public void operationComplete(IoWriteFuture future) {
        if (!future.isWritten()) {
            // Sending the request message failed
            Throwable ioe = future.getException();
            if (ioe != null) {
                setValue(ioe);
            } else {
                fail("Could not write global request " + getId() + " seqNo=" + getSequenceNumber());
            }
        }
    }

    @Override
    public String toString() {
        return super.toString() + "[seqNo=" + sequenceNumber + ']';
    }
}
