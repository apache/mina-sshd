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

import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Set;
import java.util.function.Function;
import java.util.function.ToIntFunction;

import org.apache.sshd.common.util.GenericUtils;

/**
 * A enum describing the tty modes according to <a href="https://tools.ietf.org/html/rfc4254#section-8">RFC 4254 -
 * section 8</a>.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum PtyMode {

    /////////////////////////////// Chars ////////////////////////////////////

    /**
     * Interrupt character; 255 if none. Similarly for the other characters. Not all of these characters are supported
     * on all systems.
     */
    VINTR(1),
    /**
     * The quit character (sends SIGQUIT signal on POSIX systems).
     */
    VQUIT(2),
    /**
     * Erase the character to left of the cursor.
     */
    VERASE(3),
    /**
     * Kill the current input line.
     */
    VKILL(4),
    /**
     * End-of-file character (sends EOF from the terminal).
     */
    VEOF(5),
    /**
     * End-of-line character in addition to carriage return and/or line-feed.
     */
    VEOL(6),
    /**
     * Additional end-of-line character.
     */
    VEOL2(7),
    /**
     * Continues paused output (normally control-Q).
     */
    VSTART(8),
    /**
     * Pauses output (normally control-S).
     */
    VSTOP(9),
    /**
     * Suspends the current program.
     */
    VSUSP(10),
    /**
     * Another suspend character.
     */
    VDSUSP(11),
    /**
     * Reprints the current input line.
     */
    VREPRINT(12),
    /**
     * Erases a word left of cursor.
     */
    VWERASE(13),
    /**
     * Enter the next character typed literally, even if it is a special character
     */
    VLNEXT(14),
    /**
     * Character to flush output.
     */
    VFLUSH(15),
    /**
     * Switch to a different shell layer.
     */
    VSWTCH(16),
    /**
     * Prints system status line (load, command, pid, etc).
     */
    VSTATUS(17),
    /**
     * Toggles the flushing of terminal output.
     */
    VDISCARD(18),

    ///////////////////////////////// I-flags ////////////////////////////////

    /**
     * The ignore parity flag. The parameter SHOULD be 0 if this flag is FALSE, and 1 if it is TRUE.
     */
    IGNPAR(30),
    /**
     * Mark parity and framing errors.
     */
    PARMRK(31),
    /**
     * Enable checking of parity errors.
     */
    INPCK(32),
    /**
     * Strip 8th bit off characters.
     */
    ISTRIP(33),
    /**
     * Map NL into CR on input.
     */
    INLCR(34),
    /**
     * Ignore CR on input.
     */
    IGNCR(35),
    /**
     * Map CR to NL on input.
     */
    ICRNL(36),
    /**
     * Translate uppercase characters to lowercase.
     */
    IUCLC(37),
    /**
     * Enable output flow control.
     */
    IXON(38),
    /**
     * Any char will restart after stop.
     */
    IXANY(39),
    /**
     * Enable input flow control.
     */
    IXOFF(40),
    /**
     * Ring bell on input queue full.
     */
    IMAXBEL(41),
    /**
     * @see <A HREF="https://tools.ietf.org/html/rfc8160">IUTF8 Terminal Mode in Secure Shell</A>
     */
    IUTF8(42),

    /////////////////////////////// L-flags //////////////////////////////////

    /**
     * Enable signals INTR, QUIT, [D]SUSP.
     */
    ISIG(50),
    /**
     * Canonicalize input lines.
     */
    ICANON(51),
    /**
     * Enable input and output of uppercase characters by preceding their lowercase equivalents with &quot;\&quot;.
     */
    XCASE(52),
    /**
     * Enable echoing.
     */
    ECHO(53),
    /**
     * Visually erase chars.
     */
    ECHOE(54),
    /**
     * Kill character discards current line.
     */
    ECHOK(55),
    /**
     * Echo NL even if ECHO is off.
     */
    ECHONL(56),
    /**
     * Don't flush after interrupt.
     */
    NOFLSH(57),
    /**
     * Stop background jobs from output.
     */
    TOSTOP(58),
    /**
     * Enable extensions.
     */
    IEXTEN(59),
    /**
     * Echo control characters as ^(Char).
     */
    ECHOCTL(60),
    /**
     * Visual erase for line kill.
     */
    ECHOKE(61),
    /**
     * Retype pending input.
     */
    PENDIN(62),

    /////////////////////////// O-flags //////////////////////////////////////

    /**
     * Enable output processing.
     */
    OPOST(70),
    /**
     * Convert lowercase to uppercase.
     */
    OLCUC(71),
    /**
     * Map NL to CR-NL.
     */
    ONLCR(72),
    /**
     * Translate carriage return to newline (output).
     */
    OCRNL(73),
    /**
     * Translate newline to carriage return-newline (output).
     */
    ONOCR(74),
    /**
     * Newline performs a carriage return (output).
     */
    ONLRET(75),

    //////////////////////////////// C-flags /////////////////////////////////

    /**
     * 7 bit mode.
     */
    CS7(90),
    /**
     * 8 bit mode.
     */
    CS8(91),
    /**
     * Parity enable.
     */
    PARENB(92),
    /**
     * Odd parity, else even.
     */
    PARODD(93),

    /////////////////////////// Speed(s) /////////////////////////////////////

    /**
     * Specifies the input baud rate in bits per second.
     */
    TTY_OP_ISPEED(128),
    /**
     * Specifies the output baud rate in bits per second.
     */
    TTY_OP_OSPEED(129);

    public static final byte TTY_OP_END = 0x00;

    // objects that can be used to set {@link PtyMode}s as {@code true} or {@code false}
    public static final Integer FALSE_SETTING = 0;
    public static final Integer TRUE_SETTING = 1;

    /**
     * An un-modifiable {@link Set} of all defined {@link PtyMode}s
     */
    public static final Set<PtyMode> MODES = Collections.unmodifiableSet(EnumSet.allOf(PtyMode.class));

    public static final NavigableMap<Integer, PtyMode> COMMANDS = Collections.unmodifiableNavigableMap(
            GenericUtils.toSortedMap(MODES, PtyMode::toInt, Function.identity(), Comparator.naturalOrder()));

    /**
     * A {@code null}-safe {@link ToIntFunction} that returns the {@link PtyMode#toInt()} value and (-1) for
     * {@code null}
     */
    public static final ToIntFunction<PtyMode> OPCODE_EXTRACTOR = v -> (v == null) ? -1 : v.toInt();

    /**
     * A {@code null}-safe {@link Comparator} of {@link PtyMode} values according to their {@link PtyMode#toInt()} value
     * 
     * @see #OPCODE_EXTRACTOR
     */
    public static final Comparator<PtyMode> BY_OPCODE = new Comparator<PtyMode>() {
        @Override
        public int compare(PtyMode o1, PtyMode o2) {
            int v1 = OPCODE_EXTRACTOR.applyAsInt(o1);
            int v2 = OPCODE_EXTRACTOR.applyAsInt(o2);
            return Integer.compare(v1, v2);
        }
    };

    private final int v;

    PtyMode(int v) {
        this.v = v;
    }

    public int toInt() {
        return v;
    }

    /**
     * @param  b The numeric value of the option
     * @return   The matching {@link PtyMode} or {@code null} if no match found
     * @see      #toInt()
     */
    public static PtyMode fromInt(int b) {
        return COMMANDS.get(0x00FF & b);
    }

    public static PtyMode fromName(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }

        for (PtyMode m : MODES) {
            if (name.equalsIgnoreCase(m.name())) {
                return m;
            }
        }

        return null;
    }

    /**
     * @param  options The options to enable - ignored if {@code null}/empty
     * @return         A {@link Map} where all the specified {@link PtyMode}s have {@link #TRUE_SETTING}
     */
    public static Map<PtyMode, Integer> createEnabledOptions(PtyMode... options) {
        return createEnabledOptions(GenericUtils.of(options));
    }

    /**
     * @param  options The options to enable - ignored if {@code null}/empty
     * @return         A {@link Map} where all the specified {@link PtyMode}s have {@link #TRUE_SETTING}
     */
    public static Map<PtyMode, Integer> createEnabledOptions(Collection<PtyMode> options) {
        if (GenericUtils.isEmpty(options)) {
            return Collections.emptyMap();
        }

        Map<PtyMode, Integer> modes = new EnumMap<>(PtyMode.class);
        for (PtyMode m : options) {
            modes.put(m, TRUE_SETTING);
        }

        return modes;
    }

    public static Set<PtyMode> resolveEnabledOptions(Map<PtyMode, ?> modes, PtyMode... options) {
        return resolveEnabledOptions(modes, GenericUtils.of(options));
    }

    /**
     * @param  modes   The PTY settings - ignored if {@code null}/empty
     * @param  options The options that should be enabled
     * @return         A {@link Set} of all the {@link PtyMode}s that appeared in the settings and were enabled
     * @see            #getBooleanSettingValue(Map, PtyMode)
     */
    public static Set<PtyMode> resolveEnabledOptions(Map<PtyMode, ?> modes, Collection<PtyMode> options) {
        if (GenericUtils.isEmpty(modes) || GenericUtils.isEmpty(options)) {
            return Collections.emptySet();
        }

        Set<PtyMode> enabled = EnumSet.noneOf(PtyMode.class);
        for (PtyMode m : options) {
            if (getBooleanSettingValue(modes, m)) {
                enabled.add(m);
            }
        }

        return enabled;
    }

    /**
     * @param  modes The current modes {@link Map}-ing
     * @param  m     The required {@link PtyMode}
     * @return       {@code true} if <U>all</U> of these conditions hold:</BR>
     *               <UL>
     *               <LI>Modes map is not {@code null}/empty</LI>
     *               <LI>Required mode setting is not {@code null}</LI>
     *               <LI>The setting has a mapped value</LI>
     *               <LI>The mapped value is a {@link Number}</LI>
     *               <LI>The {@link Number#intValue()} is non-zero</LI>
     *               </UL>
     * @see          #getBooleanSettingValue(Object)
     */
    public static boolean getBooleanSettingValue(Map<PtyMode, ?> modes, PtyMode m) {
        if ((m == null) || GenericUtils.isEmpty(modes)) {
            return false;
        } else {
            return getBooleanSettingValue(modes.get(m));
        }
    }

    /**
     * @param  modes        The {@link Map} of {@link PtyMode}s resolved by the &quot;pty-req&quot; message.
     * @param  enablers     A {@link Collection} of enabler settings to be consulted
     * @param  defaultValue The default value to be used if no definite setting could be deduced
     * @return              {@code true} if the CR mode is enabled:</BR>
     *                      <UL>
     *                      <LI>If<tt>modes</tt> or <tt>enablers</tt> are {@code null}/empty then <tt>defaultValue</tt>
     *                      is used</LI>
     *
     *                      <LI>If <U>any</U> of the <tt>enablers</tt> modes are enabled then the CR mode is enabled.
     *                      </LI>
     *
     *                      <LI>If <U>none</U> of the <tt>enablers</tt> modes were specified then use
     *                      <tt>defaultValue</tt></LI>
     *
     *                      <LI>Otherwise (i.e., at least one or more of the <tt>enablers</tt> modes were specified, but
     *                      <U>all</U> of them said {@code no}) then {@code false}.</LI>
     *                      </UL>
     */
    public static boolean getBooleanSettingValue(
            Map<PtyMode, ?> modes, Collection<PtyMode> enablers, boolean defaultValue) {
        if (GenericUtils.isEmpty(modes) || GenericUtils.isEmpty(enablers)) {
            return defaultValue;
        }

        int settingsCount = 0;
        for (PtyMode m : enablers) {
            Object v = modes.get(m);
            if (v == null) {
                continue;
            }

            settingsCount++;

            // if any setting says yes then use it
            if (getBooleanSettingValue(v)) {
                return true;
            }
        }

        // ALL (!) settings have said NO
        if (settingsCount > 0) {
            return false;
        } else {
            return defaultValue; // none of the settings has been found - assume default
        }
    }

    /**
     * @param  v The value to be tested
     * @return   {@code true} if <U>all</U> of these conditions hold:</BR>
     *           <UL>
     *           <LI>The mapped value is a {@link Number}</LI>
     *           <LI>The {@link Number#intValue()} is non-zero</LI>
     *           </UL>
     * @see      #getBooleanSettingValue(int)
     */
    public static boolean getBooleanSettingValue(Object v) {
        return (v instanceof Number) && getBooleanSettingValue(((Number) v).intValue());
    }

    /**
     * @param  v The setting value
     * @return   {@code true} if value is non-zero
     */
    public static boolean getBooleanSettingValue(int v) {
        return v != 0;
    }

    /**
     * @param  m The {@link PtyMode}
     * @return   {@code true} if not {@code null} and one of the settings that refers to a character value - name
     *           usually starts with {@code Vxxx}
     */
    public static boolean isCharSetting(PtyMode m) {
        if (m == null) {
            return false;
        }

        String name = m.name();
        char ch = name.charAt(0);
        return (ch == 'v') || (ch == 'V');
    }
}
