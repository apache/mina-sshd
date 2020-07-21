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

package org.apache.sshd.scp.client;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.scp.common.ScpFileOpener;
import org.apache.sshd.scp.common.ScpFileOpenerHolder;
import org.apache.sshd.scp.common.ScpTransferEventListener;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ScpClientCreator extends ScpFileOpenerHolder {
    static ScpClientCreator instance() {
        return DefaultScpClientCreator.INSTANCE;
    }

    /**
     * Create an SCP client from this session.
     *
     * @param  session The {@link ClientSession}
     * @return         An {@link ScpClient} instance. <B>Note:</B> uses the currently registered
     *                 {@link ScpTransferEventListener} and {@link ScpFileOpener} if any
     * @see            #setScpFileOpener(ScpFileOpener)
     * @see            #setScpTransferEventListener(ScpTransferEventListener)
     */
    default ScpClient createScpClient(ClientSession session) {
        return createScpClient(session, getScpFileOpener(), getScpTransferEventListener());
    }

    /**
     * Create an SCP client from this session.
     *
     * @param  session  The {@link ClientSession}
     * @param  listener A {@link ScpTransferEventListener} that can be used to receive information about the SCP
     *                  operations - may be {@code null} to indicate no more events are required. <B>Note:</B> this
     *                  listener is used <U>instead</U> of any listener set via
     *                  {@link #setScpTransferEventListener(ScpTransferEventListener)}
     * @return          An {@link ScpClient} instance
     */
    default ScpClient createScpClient(ClientSession session, ScpTransferEventListener listener) {
        return createScpClient(session, getScpFileOpener(), listener);
    }

    /**
     * Create an SCP client from this session.
     *
     * @param  session The {@link ClientSession}
     * @param  opener  The {@link ScpFileOpener} to use to control how local files are read/written. If {@code null}
     *                 then a default opener is used. <B>Note:</B> this opener is used <U>instead</U> of any instance
     *                 set via {@link #setScpFileOpener(ScpFileOpener)}
     * @return         An {@link ScpClient} instance
     */
    default ScpClient createScpClient(ClientSession session, ScpFileOpener opener) {
        return createScpClient(session, opener, getScpTransferEventListener());
    }

    /**
     * Create an SCP client from this session.
     *
     * @param  session  The {@link ClientSession}
     * @param  opener   The {@link ScpFileOpener} to use to control how local files are read/written. If {@code null}
     *                  then a default opener is used. <B>Note:</B> this opener is used <U>instead</U> of any instance
     *                  set via {@link #setScpFileOpener(ScpFileOpener)}
     * @param  listener A {@link ScpTransferEventListener} that can be used to receive information about the SCP
     *                  operations - may be {@code null} to indicate no more events are required. <B>Note:</B> this
     *                  listener is used <U>instead</U> of any listener set via
     *                  {@link #setScpTransferEventListener(ScpTransferEventListener)}
     * @return          An {@link ScpClient} instance
     */
    ScpClient createScpClient(ClientSession session, ScpFileOpener opener, ScpTransferEventListener listener);

    /**
     * @return The last {@link ScpTransferEventListener} set via
     *         {@link #setScpTransferEventListener(ScpTransferEventListener)}
     */
    ScpTransferEventListener getScpTransferEventListener();

    /**
     * @param listener A default {@link ScpTransferEventListener} that can be used to receive information about the SCP
     *                 operations - may be {@code null} to indicate no more events are required
     * @see            #createScpClient(ClientSession, ScpTransferEventListener)
     */
    void setScpTransferEventListener(ScpTransferEventListener listener);
}
