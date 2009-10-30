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
package org.apache.sshd.common.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.TreeMap;

import org.apache.sshd.common.PtyMode;

/**
 * Support for stty command on unix
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SttySupport {

    private static String sttyCommand = System.getProperty("sshd.sttyCommand", "stty");
    private static String ttyProps;
    private static long ttyPropsLastFetched;

    public static Map<PtyMode, Integer> getUnixPtyModes() throws IOException, InterruptedException {
        return parsePtyModes(getTtyProps());
    }

    public static Map<PtyMode, Integer> parsePtyModes(String stty) {
        Map<PtyMode, Integer> modes = new TreeMap<PtyMode, Integer>();
        for (PtyMode mode : PtyMode.values()) {
            if (mode == PtyMode.TTY_OP_ISPEED || mode == PtyMode.TTY_OP_OSPEED) {

            } else {
                String str = mode.name().toLowerCase();
                // Are we looking for a character?
                if (str.charAt(0) == 'v') {
                    str = str.substring(1);
                    int v = findChar(stty, str);
                    if (v < 0 && "reprint".equals(str)) {
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
            if (idx1 > 0 && Character.isLetterOrDigit(stty.charAt(idx1 - 1))
                    || (idx2 < stty.length() && Character.isLetterOrDigit(stty.charAt(idx2)))) {
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
            if (val.indexOf("undef") >= 0) {
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
     *  Returns the value of "stty size" width param.
     *
     *  <strong>Note</strong>: this method caches the value from the
     *  first time it is called in order to increase speed, which means
     *  that changing to size of the terminal will not be reflected
     *  in the console.
     */
    public static int getTerminalWidth() {
        int val = -1;

        try {
            val = getTerminalProperty("columns");
        } catch (Exception e) {
        }

        if (val == -1) {
            val = 80;
        }

        return val;
    }

    /**
     *  Returns the value of "stty size" height param.
     *
     *  <strong>Note</strong>: this method caches the value from the
     *  first time it is called in order to increase speed, which means
     *  that changing to size of the terminal will not be reflected
     *  in the console.
     */
    public static int getTerminalHeight() {
        int val = -1;

        try {
            val = getTerminalProperty("rows");
        } catch (Exception e) {
        }

        if (val == -1) {
            val = 24;
        }

        return val;
    }

    private static int getTerminalProperty(String prop)
                                    throws IOException, InterruptedException {
        // need to be able handle both output formats:
        // speed 9600 baud; 24 rows; 140 columns;
        // and:
        // speed 38400 baud; rows = 49; columns = 111; ypixels = 0; xpixels = 0;
        for (StringTokenizer tok = new StringTokenizer(getTtyProps(), ";\n");
                 tok.hasMoreTokens();) {
            String str = tok.nextToken().trim();

            if (str.startsWith(prop)) {
                int index = str.lastIndexOf(" ");

                return Integer.parseInt(str.substring(index).trim());
            } else if (str.endsWith(prop)) {
                int index = str.indexOf(" ");

                return Integer.parseInt(str.substring(0, index).trim());
            }
        }

        return -1;
    }

    public static String getTtyProps() throws IOException, InterruptedException {
        // tty properties are cached so we don't have to worry too much about getting term widht/height
        if (ttyProps == null || System.currentTimeMillis() - ttyPropsLastFetched > 1000) {
            ttyProps = stty("-a");
            ttyPropsLastFetched = System.currentTimeMillis();
        }
        return ttyProps;
    }


    /**
     *  Execute the stty command with the specified arguments
     *  against the current active terminal.
     */
    public static String stty(final String args)
                        throws IOException, InterruptedException {
        return exec("stty " + args + " < /dev/tty").trim();
    }

    /**
     *  Execute the specified command and return the output
     *  (both stdout and stderr).
     */
    public static String exec(final String cmd)
                        throws IOException, InterruptedException {
        return exec(new String[] {
                        "sh",
                        "-c",
                        cmd
                    });
    }

    /**
     *  Execute the specified command and return the output
     *  (both stdout and stderr).
     */
    private static String exec(final String[] cmd)
                        throws IOException, InterruptedException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();

        Process p = Runtime.getRuntime().exec(cmd);
        int c;
        InputStream in;

        in = p.getInputStream();

        while ((c = in.read()) != -1) {
            bout.write(c);
        }

        in = p.getErrorStream();

        while ((c = in.read()) != -1) {
            bout.write(c);
        }

        p.waitFor();

        String result = new String(bout.toByteArray());

        return result;
    }

    /**
     *  The command to use to set the terminal options. Defaults
     *  to "stty", or the value of the system property "jline.sttyCommand".
     */
    public static void setSttyCommand(String cmd) {
        sttyCommand = cmd;
    }

    /**
     *  The command to use to set the terminal options. Defaults
     *  to "stty", or the value of the system property "jline.sttyCommand".
     */
    public static String getSttyCommand() {
        return sttyCommand;
    }

}
