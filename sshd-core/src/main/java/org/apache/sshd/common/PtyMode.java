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
package org.apache.sshd.common;

import java.util.HashMap;
import java.util.Map;

/**
 * A enum describing the tty modes.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum PtyMode {

    // Chars
    VINTR(1), VQUIT(2), VERASE(3), VKILL(4), VEOF(5), VEOL(6), VEOL2(7), VSTART(8), VSTOP(9),
    VSUSP(10), VDSUSP(11), VREPRINT(12), VWERASE(13), VLNEXT(14), VFLUSH(15), VSWTCH(16), VSTATUS(17), VDISCARD(18),

    // I flags
    IGNPAR(30), PARMRK(31), INPCK(32), ISTRIP(33), INLCR(34), IGNCR(35), ICRNL(36), IUCLC(37), IXON(38), IXANY(39),
    IXOFF(40), IMAXBEL(41),

    // L flags
    ISIG(50), ICANON(51), XCASE(52), ECHO(53), ECHOE(54), ECHOK(55), ECHONL(56), NOFLSH(57), TOSTOP(58), IEXTEN(59),
    ECHOCTL(60), ECHOKE(61), PENDIN(62),

    // O flags
    OPOST(70), OLCUC(71), ONLCR(72), OCRNL(73), ONOCR(74), ONLRET(75),

    // C flags
    CS7(90), CS8(91), PARENB(92), PARODD(93),

    // Speeed
    TTY_OP_ISPEED(128), TTY_OP_OSPEED(129);

    private int v;

    private PtyMode(int v) {
        this.v = v;
    }

    public int toInt() {
        return v;
    }

    static Map<Integer, PtyMode> commands;

    static {
        commands = new HashMap<Integer, PtyMode>();
        for (PtyMode c : PtyMode.values()) {
            commands.put(c.toInt(), c);
        }
    }

    public static PtyMode fromInt(int b) {
        return commands.get(0x00FF & (b + 256));
    }
}
