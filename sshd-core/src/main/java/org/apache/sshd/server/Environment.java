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
package org.apache.sshd.server;

import org.apache.sshd.common.PtyMode;

import java.util.EnumSet;
import java.util.Map;

/**
 * Interface providing access to the environment map and allowing the registration
 * of listeners for certain signals.
 *
 * @see org.apache.sshd.server.Signal
 */
public interface Environment {
    /**
     * Key for the user environment variable
     */
    public static final String ENV_USER = "USER";
    /**
     * Key for the lines environment variable. Specifies the number of
     * lines visible on the client side. {@link Environment#ENV_LINES} and
     * {@link Environment#ENV_COLUMNS} make up the console screen size.
     */
    public static final String ENV_LINES = "LINES";
    /**
     * Key for the columns environment variable. Specifies the number of
     * columns visible on the client side. {@link Environment#ENV_LINES} and
     * {@link Environment#ENV_COLUMNS} make up the console screen size.
     */
    public static final String ENV_COLUMNS = "COLUMNS";
    /**
     * Key for the term environment variable. Describes the terminal or
     * terminal emulation which is in use.
     */
    public static final String ENV_TERM = "TERM";

    /**
     * Retrieve the environment map
     * @return the environment map
     */
    Map<String, String> getEnv();

    /**
     * Retrieve the pty modes
     * @return the map of pty modes
     */
    Map<PtyMode, Integer> getPtyModes();

    /**
     * Add a qualified listener for the specific signal
     * @param listener the listener to register
     * @param signal the signal the listener is interested in
     */
    void addSignalListener(SignalListener listener, Signal... signal);

    /**
     * Add a qualified listener for the specific set of signal
     * @param listener the listener to register
     * @param signals the signals the listener is interested in
     */
    void addSignalListener(SignalListener listener, EnumSet<Signal> signals);

    /**
     * Add a global listener for all signals
     * @param listener the listener to register
     */
    void addSignalListener(SignalListener listener);

    /**
     * Remove a previously registered listener for all the signals it was registered
     * @param listener the listener to remove
     */
    void removeSignalListener(SignalListener listener);
}
