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

import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.NavigableMap;
import java.util.Set;
import java.util.function.Function;

import org.apache.sshd.common.util.GenericUtils;

/**
 * System signals definition that the shell can receive.
 */
public enum Signal {
    HUP(1),
    INT(2),
    QUIT(3),
    ILL(4),
    TRAP(5),
    IOT(6),
    BUS(7),
    FPE(8),
    KILL(9),
    USR1(10),
    SEGV(11),
    USR2(12),
    PIPE(13),
    ALRM(14),
    TERM(15),
    STKFLT(16),
    CHLD(17),
    CONT(18),
    STOP(19),
    TSTP(20),
    TTIN(21),
    TTOU(22),
    URG(23),
    XCPU(24),
    XFSZ(25),
    VTALRM(26),
    PROF(27),
    WINCH(28),
    IO(29),
    PWR(30);

    /**
     * An un-modifiable {@link Set} of all the available {@link Signal}s
     */
    public static final Set<Signal> SIGNALS = Collections.unmodifiableSet(EnumSet.allOf(Signal.class));

    /**
     * An un-modifiable <U>case-insensitive</U> {@link NavigableMap} of the names of all available {@link Signal}s
     * 
     * @see #SIGNALS
     */
    public static final NavigableMap<String, Signal> NAME_LOOKUP_TABLE = Collections.unmodifiableNavigableMap(
            GenericUtils.toSortedMap(SIGNALS, Signal::name, Function.identity(), String.CASE_INSENSITIVE_ORDER));

    /**
     * An un-modifiable {@link NavigableMap} of the numeric values of all available {@link Signal}s
     * 
     * @see #SIGNALS
     * @see #getNumeric()
     */
    public static final NavigableMap<Integer, Signal> NUMERIC_LOOKUP_TABLE = Collections.unmodifiableNavigableMap(
            GenericUtils.toSortedMap(SIGNALS, Signal::getNumeric, Function.identity(), Comparator.naturalOrder()));

    private final int numeric;

    Signal(int numeric) {
        this.numeric = numeric;
    }

    /**
     * @return The signal's numeric value
     */
    public int getNumeric() {
        return numeric;
    }

    /**
     * Retrieves a signal value given its name
     *
     * @param  name The signal's name (case <U>insensitive</U>) - ignored if {@code null}/empty
     * @return      The matching {@link Signal} or {@code null} if no match found
     */
    public static Signal get(String name) {
        return GenericUtils.isEmpty(name) ? null : NAME_LOOKUP_TABLE.get(name);
    }

    /**
     * Retrieves a signal value given its numeric value
     *
     * @param  num The signal's numeric value
     * @return     The matching {@link Signal} or {@code null} if no match found
     * @see        #getNumeric()
     */
    public static Signal get(int num) {
        return NUMERIC_LOOKUP_TABLE.get(num);
    }
}
