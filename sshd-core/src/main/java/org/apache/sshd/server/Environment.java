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
package org.apache.sshd.server;

import java.util.Collection;
import java.util.Map;

import org.apache.sshd.common.channel.PtyMode;
import org.apache.sshd.common.util.GenericUtils;

/**
 * Interface providing access to the environment map and allowing the registration of listeners for certain signals.
 *
 * @see org.apache.sshd.server.Signal
 */
public interface Environment {
    /**
     * Key for the user environment variable
     */
    String ENV_USER = "USER";

    /**
     * Key for the lines environment variable. Specifies the number of lines visible on the client side.
     * {@link #ENV_LINES} and {@link #ENV_COLUMNS} make up the console screen size.
     */
    String ENV_LINES = "LINES";

    /**
     * Key for the columns environment variable. Specifies the number of columns visible on the client side.
     * {@link #ENV_LINES} and {@link #ENV_COLUMNS} make up the console screen size.
     */
    String ENV_COLUMNS = "COLUMNS";

    /**
     * Key for the term environment variable. Describes the terminal or terminal emulation which is in use.
     */
    String ENV_TERM = "TERM";

    /**
     * Retrieve the environment map
     *
     * @return the environment {@link Map} - never {@code null}
     */
    Map<String, String> getEnv();

    /**
     * Retrieve the PTY modes settings
     *
     * @return the {@link Map} of {@link PtyMode}s - never {@code null}
     */
    Map<PtyMode, Integer> getPtyModes();

    /**
     * Add a qualified listener for the specific signals
     *
     * @param listener the {@link SignalListener} to register
     * @param signals  The (never {@code null}/empty) {@link Signal}s the listener is interested in
     */
    default void addSignalListener(SignalListener listener, Signal... signals) {
        addSignalListener(listener, GenericUtils.of(signals));
    }

    /**
     * Add a global listener for all signals
     *
     * @param listener the {@link SignalListener} to register
     */
    default void addSignalListener(SignalListener listener) {
        addSignalListener(listener, Signal.SIGNALS);
    }

    /**
     * Add a qualified listener for the specific signals
     *
     * @param listener the {@link SignalListener} to register
     * @param signals  the {@link Signal}s the listener is interested in
     */
    void addSignalListener(SignalListener listener, Collection<Signal> signals);

    /**
     * Remove a previously registered listener for all the signals it was registered
     *
     * @param listener the {@link SignalListener} to remove
     */
    void removeSignalListener(SignalListener listener);
}
