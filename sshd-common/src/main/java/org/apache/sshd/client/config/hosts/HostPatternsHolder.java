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

package org.apache.sshd.client.config.hosts;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class HostPatternsHolder {

    /**
     * Used in a host pattern to denote zero or more consecutive characters
     */
    public static final char WILDCARD_PATTERN = '*';
    public static final String ALL_HOSTS_PATTERN = String.valueOf(WILDCARD_PATTERN);

    /**
     * Used in a host pattern to denote any <U>one</U> character
     */
    public static final char SINGLE_CHAR_PATTERN = '?';

    /**
     * Used to negate a host pattern
     */
    public static final char NEGATION_CHAR_PATTERN = '!';

    /**
     * The available pattern characters
     */
    public static final String PATTERN_CHARS
            = new String(new char[] { WILDCARD_PATTERN, SINGLE_CHAR_PATTERN, NEGATION_CHAR_PATTERN });

    /** Port value separator if non-standard port pattern used */
    public static final char PORT_VALUE_DELIMITER = ':';

    /** Non-standard port specification host pattern enclosure start delimiter */
    public static final char NON_STANDARD_PORT_PATTERN_ENCLOSURE_START_DELIM = '[';

    /** Non-standard port specification host pattern enclosure end delimiter */
    public static final char NON_STANDARD_PORT_PATTERN_ENCLOSURE_END_DELIM = ']';

    private Collection<HostPatternValue> patterns = new LinkedList<>();

    protected HostPatternsHolder() {
        super();
    }

    public Collection<HostPatternValue> getPatterns() {
        return patterns;
    }

    public void setPatterns(Collection<HostPatternValue> patterns) {
        this.patterns = patterns;
    }

    /**
     * Checks if a given host name / address matches the entry's host pattern(s)
     *
     * @param  host The host name / address - ignored if {@code null}/empty
     * @param  port The connection port
     * @return      {@code true} if the name / address matches the pattern(s)
     * @see         #isHostMatch(String, Pattern)
     */
    public boolean isHostMatch(String host, int port) {
        return isHostMatch(host, port, getPatterns());
    }

    /**
     * @param  pattern The pattern to check - ignored if {@code null}/empty
     * @return         {@code true} if the pattern is not empty and contains no wildcard characters
     * @see            #WILDCARD_PATTERN
     * @see            #SINGLE_CHAR_PATTERN
     * @see            #SINGLE_CHAR_PATTERN
     */
    public static boolean isSpecificHostPattern(String pattern) {
        if (GenericUtils.isEmpty(pattern)) {
            return false;
        }

        for (int index = 0; index < PATTERN_CHARS.length(); index++) {
            char ch = PATTERN_CHARS.charAt(index);
            if (pattern.indexOf(ch) >= 0) {
                return false;
            }
        }

        return true;
    }

    /**
     * Locates all the matching entries for a give host name / address
     *
     * @param  host    The host name / address - ignored if {@code null}/empty
     * @param  entries The {@link HostConfigEntry}-ies to scan - ignored if {@code null}/empty
     * @return         A {@link List} of all the matching entries
     * @see            #isHostMatch(String, int)
     */
    public static List<HostConfigEntry> findMatchingEntries(String host, HostConfigEntry... entries) {
        // TODO in Java-8 use Stream(s) + predicate
        if (GenericUtils.isEmpty(host) || GenericUtils.isEmpty(entries)) {
            return Collections.emptyList();
        } else {
            return findMatchingEntries(host, Arrays.asList(entries));
        }
    }

    /**
     * Locates all the matching entries for a give host name / address
     *
     * @param  host    The host name / address - ignored if {@code null}/empty
     * @param  entries The {@link HostConfigEntry}-ies to scan - ignored if {@code null}/empty
     * @return         A {@link List} of all the matching entries
     * @see            #isHostMatch(String, int)
     */
    public static List<HostConfigEntry> findMatchingEntries(String host, Collection<? extends HostConfigEntry> entries) {
        // TODO in Java-8 use Stream(s) + predicate
        if (GenericUtils.isEmpty(host) || GenericUtils.isEmpty(entries)) {
            return Collections.emptyList();
        }

        List<HostConfigEntry> matches = null;
        for (HostConfigEntry entry : entries) {
            if (!entry.isHostMatch(host, 0 /* any port */)) {
                continue; // debug breakpoint
            }

            if (matches == null) {
                matches = new ArrayList<>(entries.size()); // in case ALL of them match
            }

            matches.add(entry);
        }

        if (matches == null) {
            return Collections.emptyList();
        } else {
            return matches;
        }
    }

    public static boolean isHostMatch(String host, int port, Collection<HostPatternValue> patterns) {
        if (GenericUtils.isEmpty(patterns)) {
            return false;
        }

        boolean matchFound = false;
        for (HostPatternValue pv : patterns) {
            boolean negated = pv.isNegated();
            /*
             * If already found a match we are interested only in negations
             */
            if (matchFound && (!negated)) {
                continue;
            }

            if (!isHostMatch(host, pv.getPattern())) {
                continue;
            }

            if (!isPortMatch(port, pv.getPort())) {
                continue;
            }

            /*
             * According to https://www.freebsd.org/cgi/man.cgi?query=ssh_config&sektion=5:
             *
             * If a negated entry is matched, then the Host entry is ignored, regardless of whether any other patterns
             * on the line match.
             */
            if (negated) {
                return false;
            }

            matchFound = true;
        }

        return matchFound;
    }

    /**
     * @param  port1 1st port value - if non-positive the assumed to be {@link SshConstants#DEFAULT_PORT DEFAULT_PORT}
     * @param  port2 2nd port value - if non-positive the assumed to be {@link SshConstants#DEFAULT_PORT DEFAULT_PORT}
     * @return       {@code true} if ports are effectively equal
     */
    public static boolean isPortMatch(int port1, int port2) {
        return SshConstants.TO_EFFECTIVE_PORT.applyAsInt(port1) == SshConstants.TO_EFFECTIVE_PORT.applyAsInt(port2);
    }

    /**
     * Checks if a given host name / address matches a host pattern
     *
     * @param  host    The host name / address - ignored if {@code null}/empty
     * @param  pattern The host {@link Pattern} - ignored if {@code null}
     * @return         {@code true} if the name / address matches the pattern
     */
    public static boolean isHostMatch(String host, Pattern pattern) {
        if (GenericUtils.isEmpty(host) || (pattern == null)) {
            return false;
        }

        Matcher m = pattern.matcher(host);
        return m.matches();
    }

    public static List<HostPatternValue> parsePatterns(CharSequence... patterns) {
        return parsePatterns(GenericUtils.isEmpty(patterns) ? Collections.emptyList() : Arrays.asList(patterns));
    }

    public static List<HostPatternValue> parsePatterns(Collection<? extends CharSequence> patterns) {
        if (GenericUtils.isEmpty(patterns)) {
            return Collections.emptyList();
        }

        List<HostPatternValue> result = new ArrayList<>(patterns.size());
        for (CharSequence p : patterns) {
            result.add(ValidateUtils.checkNotNull(toPattern(p), "No pattern for %s", p));
        }

        return result;
    }

    /**
     * Converts a host pattern string to a regular expression matcher. <B>Note:</B> pattern matching is <U>case
     * insensitive</U>
     *
     * @param  patternString The original pattern string - ignored if {@code null}/empty
     * @return               The regular expression matcher {@link Pattern} and the indication whether it is a negating
     *                       pattern or not - {@code null} if no original string
     * @see                  #NON_STANDARD_PORT_PATTERN_ENCLOSURE_START_DELIM
     * @see                  #NON_STANDARD_PORT_PATTERN_ENCLOSURE_END_DELIM
     * @see                  #WILDCARD_PATTERN
     * @see                  #SINGLE_CHAR_PATTERN
     * @see                  #NEGATION_CHAR_PATTERN
     */
    public static HostPatternValue toPattern(CharSequence patternString) {
        String pattern = GenericUtils.replaceWhitespaceAndTrim(Objects.toString(patternString, null));
        if (GenericUtils.isEmpty(pattern)) {
            return null;
        }

        int patternLen = pattern.length();
        int port = 0;
        // Check if non-standard port value used
        StringBuilder sb = new StringBuilder(patternLen);
        if (pattern.charAt(0) == HostPatternsHolder.NON_STANDARD_PORT_PATTERN_ENCLOSURE_START_DELIM) {
            int pos = GenericUtils.lastIndexOf(pattern, HostPatternsHolder.PORT_VALUE_DELIMITER);
            ValidateUtils.checkTrue(pos > 0, "Missing non-standard port value delimiter in %s", pattern);
            ValidateUtils.checkTrue(pos < (patternLen - 1), "Missing non-standard port value number in %s", pattern);
            ValidateUtils.checkTrue(pattern.charAt(pos - 1) == HostPatternsHolder.NON_STANDARD_PORT_PATTERN_ENCLOSURE_END_DELIM,
                    "Invalid non-standard port value host pattern enclosure delimiters in %s", pattern);

            String csPort = pattern.substring(pos + 1, patternLen);
            port = Integer.parseInt(csPort);
            ValidateUtils.checkTrue((port > 0) && (port <= 0xFFFF), "Invalid non-start port value (%d) in %s", port, pattern);

            pattern = pattern.substring(1, pos - 1);
            patternLen = pattern.length();
        }

        boolean negated = false;
        for (int curPos = 0; curPos < patternLen; curPos++) {
            char ch = pattern.charAt(curPos);
            ValidateUtils.checkTrue(isValidPatternChar(ch), "Invalid host pattern char in %s", pattern);

            switch (ch) {
                case '.': // need to escape it
                    sb.append('\\').append(ch);
                    break;
                case SINGLE_CHAR_PATTERN:
                    sb.append('.');
                    break;
                case WILDCARD_PATTERN:
                    sb.append(".*");
                    break;
                case NEGATION_CHAR_PATTERN:
                    ValidateUtils.checkTrue(!negated, "Double negation in %s", pattern);
                    ValidateUtils.checkTrue(curPos == 0, "Negation must be 1st char: %s", pattern);
                    negated = true;
                    break;
                default:
                    sb.append(ch);
            }
        }

        return new HostPatternValue(Pattern.compile(sb.toString(), Pattern.CASE_INSENSITIVE), port, negated);
    }

    /**
     * Checks if the given character is valid for a host pattern. Valid characters are:
     * <UL>
     * <LI>A-Z</LI>
     * <LI>a-z</LI>
     * <LI>0-9</LI>
     * <LI>Underscore (_)</LI>
     * <LI>Hyphen (-)</LI>
     * <LI>Dot (.)</LI>
     * <LI>Colon (:)</LI>
     * <LI>Percent (%) for scoped ipv6</LI>
     * <LI>The {@link #WILDCARD_PATTERN}</LI>
     * <LI>The {@link #SINGLE_CHAR_PATTERN}</LI>
     * </UL>
     *
     * @param  ch The character to validate
     * @return    {@code true} if valid pattern character
     */
    public static boolean isValidPatternChar(char ch) {
        if ((ch <= ' ') || (ch >= 0x7E)) {
            return false;
        }
        if ((ch >= 'a') && (ch <= 'z')) {
            return true;
        }
        if ((ch >= 'A') && (ch <= 'Z')) {
            return true;
        }
        if ((ch >= '0') && (ch <= '9')) {
            return true;
        }
        if ("-_.:%".indexOf(ch) >= 0) {
            return true;
        }
        return PATTERN_CHARS.indexOf(ch) >= 0;
    }
}
