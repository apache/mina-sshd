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

import java.util.HashMap;
import java.util.Map;

/**
 * System signals definition that the shell can receive.
 *
 * @see Environment
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

    private static final Map<String, Signal> lookupTable = new HashMap<String, Signal>(40);

    static {
        // registering the signals in the lookup table to allow faster
        // string based signal lookups
        for (Signal s : Signal.values()) {
            lookupTable.put(s.name(), s);
        }
    }

    public static Signal get(String name) {
        return lookupTable.get(name);
    }

    private final int numeric;

    private Signal(int numeric) {
        this.numeric = numeric;
    }

    public int getNumeric() {
        return numeric;
    }
}
