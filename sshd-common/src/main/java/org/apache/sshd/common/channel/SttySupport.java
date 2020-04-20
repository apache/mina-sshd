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
package org.apache.sshd.common.channel;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.EnumMap;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Support for stty command on unix
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class SttySupport {
    public static final int DEFAULT_TERMINAL_WIDTH = 80;
    public static final int DEFAULT_TERMINAL_HEIGHT = 24;

    public static final String SSHD_STTY_COMMAND_PROP = "sshd.sttyCommand";
    public static final String DEFAULT_SSHD_STTY_COMMAND = "stty";

    private static final AtomicReference<String> STTY_COMMAND_HOLDER
            = new AtomicReference<>(System.getProperty(SSHD_STTY_COMMAND_PROP, DEFAULT_SSHD_STTY_COMMAND));
    private static final AtomicReference<String> TTY_PROPS_HOLDER = new AtomicReference<>(null);
    private static final AtomicLong TTY_PROPS_LAST_FETCHED_HOLDER = new AtomicLong(0L);

    private SttySupport() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    public static Map<PtyMode, Integer> getUnixPtyModes() throws IOException, InterruptedException {
        return parsePtyModes(getTtyProps());
    }

    public static Map<PtyMode, Integer> parsePtyModes(String stty) {
        Map<PtyMode, Integer> modes = new EnumMap<>(PtyMode.class);
        for (PtyMode mode : PtyMode.MODES) {
            if ((mode == PtyMode.TTY_OP_ISPEED) || (mode == PtyMode.TTY_OP_OSPEED)) {
                // TODO ...
                continue;
            }

            String str = mode.name().toLowerCase();
            // Are we looking for a character?
            if (str.charAt(0) == 'v') {
                str = str.substring(1);
                int v = findChar(stty, str);
                if ((v < 0) && "reprint".equals(str)) {
                    v = findChar(stty, "rprnt");
                }
                if (v >= 0) {
                    modes.put(mode, v);
                }
            } else {
                int v = findFlag(stty, str);
                if (v >= 0) {
                    modes.put(mode, v);
                }
            }
        }

        return modes;
    }

    private static int findFlag(String stty, String name) {
        int cur = 0;
        while (cur < stty.length()) {
            int idx1 = stty.indexOf(name, cur);
            int idx2 = idx1 + name.length();
            if (idx1 < 0) {
                return -1;
            }
            if ((idx1 > 0) && Character.isLetterOrDigit(stty.charAt(idx1 - 1))
                    || ((idx2 < stty.length()) && Character.isLetterOrDigit(stty.charAt(idx2)))) {
                cur = idx2;
                continue;
            }
            return idx1 == 0 ? 1 : stty.charAt(idx1 - 1) == '-' ? 0 : 1;
        }
        return -1;
    }

    private static int findChar(String stty, String name) {
        int cur = 0;
        while (cur < stty.length()) {
            int idx1 = stty.indexOf(name, cur);
            int idx2 = stty.indexOf('=', idx1);
            int idx3 = stty.indexOf(';', idx1);
            if (idx1 < 0 || idx2 < 0 || idx3 < idx2) {
                // Invalid syntax
                return -1;
            }
            if (idx1 > 0 && Character.isLetterOrDigit(stty.charAt(idx1 - 1))
                    || (idx2 < stty.length() && Character.isLetterOrDigit(stty.charAt(idx2)))) {
                cur = idx1 + name.length();
                continue;
            }
            String val = stty.substring(idx2 + 1, idx3 < 0 ? stty.length() : idx3).trim();
            if (val.contains("undef")) {
                return -1;
            }
            if (val.length() == 2 && val.charAt(0) == '^') {
                int v = (val.charAt(1) - 'A' + 129) % 128;
                return v;
            } else {
                try {
                    return Integer.parseInt(val);
                } catch (NumberFormatException e) {
                    // what else ?
                }
            }
            return -1;
        }
        return -1;
    }

    /**
     * <P>
     * Returns the value of "stty size" width param.
     * </P>
     *
     * <P>
     * <strong>Note</strong>: this method caches the value from the first time it is called in order to increase speed,
     * which means that changing to size of the terminal will not be reflected in the console.
     * </P>
     *
     * @return The terminal width
     */
    public static int getTerminalWidth() {
        try {
            int val = getTerminalProperty("columns");
            if (val == -1) {
                val = DEFAULT_TERMINAL_WIDTH;
            }

            return val;
        } catch (Exception e) {
            return DEFAULT_TERMINAL_WIDTH; // debug breakpoint
        }
    }

    /**
     * <P>
     * Returns the value of "stty size" height param.
     * </P>
     *
     * <P>
     * <strong>Note</strong>: this method caches the value from the first time it is called in order to increase speed,
     * which means that changing to size of the terminal will not be reflected in the console.
     * </P>
     *
     * @return The terminal height
     */
    public static int getTerminalHeight() {
        try {
            int val = getTerminalProperty("rows");
            if (val == -1) {
                val = DEFAULT_TERMINAL_HEIGHT;
            }

            return val;
        } catch (Exception e) {
            return DEFAULT_TERMINAL_HEIGHT; // debug breakpoint
        }
    }

    public static int getTerminalProperty(String prop) throws IOException, InterruptedException {
        // need to be able handle both output formats:
        // speed 9600 baud; 24 rows; 140 columns;
        // and:
        // speed 38400 baud; rows = 49; columns = 111; ypixels = 0; xpixels = 0;
        for (StringTokenizer tok = new StringTokenizer(getTtyProps(), ";\n"); tok.hasMoreTokens();) {
            String str = tok.nextToken().trim();

            if (str.startsWith(prop)) {
                int index = str.lastIndexOf(' ');

                return Integer.parseInt(str.substring(index).trim());
            } else if (str.endsWith(prop)) {
                int index = str.indexOf(' ');

                return Integer.parseInt(str.substring(0, index).trim());
            }
        }

        return -1;
    }

    public static String getTtyProps() throws IOException, InterruptedException {
        // tty properties are cached so we don't have to worry too much about getting term width/height
        long now = System.currentTimeMillis();
        long lastFetched = TTY_PROPS_LAST_FETCHED_HOLDER.get();
        if ((TTY_PROPS_HOLDER.get() == null) || ((now - lastFetched) > 1000L)) {
            TTY_PROPS_HOLDER.set(stty("-a"));
            TTY_PROPS_LAST_FETCHED_HOLDER.set(System.currentTimeMillis());
        }

        return TTY_PROPS_HOLDER.get();
    }

    /**
     * Execute the stty command with the specified arguments against the current active terminal.
     *
     * @param  args                 The command arguments
     * @return                      The execution result
     * @throws IOException          If failed to execute the command
     * @throws InterruptedException If interrupted while awaiting command execution
     * @see                         #exec(String)
     */
    public static String stty(String args) throws IOException, InterruptedException {
        return exec("stty " + args + " < /dev/tty").trim();
    }

    /**
     * Execute the specified command and return the output (both stdout and stderr).
     *
     * @param  cmd                  The command to execute
     * @return                      The execution result
     * @throws IOException          If failed to execute the command
     * @throws InterruptedException If interrupted while awaiting command execution
     * @see                         #exec(String[])
     */
    public static String exec(final String cmd)
            throws IOException, InterruptedException {
        return exec("sh", "-c", cmd);
    }

    /**
     * Execute the specified command and return the output (both stdout and stderr).
     *
     * @param  cmd                  The command components
     * @return                      The execution result
     * @throws IOException          If failed to execute the command
     * @throws InterruptedException If interrupted while awaiting command execution
     */
    private static String exec(String... cmd)
            throws IOException, InterruptedException {
        try (ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
            Process p = Runtime.getRuntime().exec(cmd);
            copyStream(p.getInputStream(), bout);
            copyStream(p.getErrorStream(), bout);
            p.waitFor();

            String result = new String(bout.toByteArray(), Charset.defaultCharset());
            return result;
        }
    }

    private static int copyStream(InputStream in, OutputStream bout) throws IOException {
        int count = 0;
        while (true) {
            int c = in.read();
            if (c == -1) {
                return count;
            }

            bout.write(c);
            count++;
        }
    }

    /**
     * @return The command to use to set the terminal options.
     * @see    #setSttyCommand(String)
     */
    public static String getSttyCommand() {
        return STTY_COMMAND_HOLDER.get();
    }

    /**
     * @param cmd The command to use to set the terminal options. Defaults to {@link #DEFAULT_SSHD_STTY_COMMAND}, or the
     *            value of the {@link #SSHD_STTY_COMMAND_PROP} system property if not set via this method
     */
    public static void setSttyCommand(String cmd) {
        STTY_COMMAND_HOLDER.set(cmd);
    }
}
