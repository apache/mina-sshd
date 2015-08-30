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

import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface KeyExchangeFuture extends SshFuture<KeyExchangeFuture> {
    /**
     * Wait and verify that the exchange has been successful
     *
     * @throws IOException if the action failed for any reason
     */
    void verify() throws IOException;

    /**
     * Wait and verify that the exchange has been successful
     *
     * @param timeout The number of time units to wait
     * @param unit    The wait {@link TimeUnit}
     * @throws IOException If failed to verify successfully on time
     */
    void verify(long timeout, TimeUnit unit) throws IOException;

    /**
     * Wait and verify that the exchange has been successful
     *
     * @param timeoutMillis Wait timeout in milliseconds
     * @throws IOException If failed to verify successfully on time
     */
    void verify(long timeoutMillis) throws IOException;

    /**
     * Returns the cause of the exchange failure.
     *
     * @return <code>null</code> if the exchange operation is not finished yet,
     * or if the exchange attempt is successful.
     */
    Throwable getException();
}
