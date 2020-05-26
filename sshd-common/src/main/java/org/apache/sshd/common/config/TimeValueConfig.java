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

package org.apache.sshd.common.config;

import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="http://unixhelp.ed.ac.uk/CGI/man-cgi?sshd_config+5">Time formats for SSH configuration values</A>
 */
public enum TimeValueConfig {
    SECONDS('s', 'S', TimeUnit.SECONDS.toMillis(1L)),
    MINUTES('m', 'M', TimeUnit.MINUTES.toMillis(1L)),
    HOURS('h', 'H', TimeUnit.HOURS.toMillis(1L)),
    DAYS('d', 'D', TimeUnit.DAYS.toMillis(1L)),
    WEEKS('w', 'W', TimeUnit.DAYS.toMillis(7L));

    public static final Set<TimeValueConfig> VALUES = Collections.unmodifiableSet(EnumSet.allOf(TimeValueConfig.class));

    private final char loChar;
    private final char hiChar;
    private final long interval;

    TimeValueConfig(char lo, char hi, long interval) {
        loChar = lo;
        hiChar = hi;
        this.interval = interval;
    }

    public final char getLowerCaseValue() {
        return loChar;
    }

    public final char getUpperCaseValue() {
        return hiChar;
    }

    public final long getInterval() {
        return interval;
    }

    public static TimeValueConfig fromValueChar(char ch) {
        if ((ch <= ' ') || (ch >= 0x7F)) {
            return null;
        }

        for (TimeValueConfig v : VALUES) {
            if ((v.getLowerCaseValue() == ch) || (v.getUpperCaseValue() == ch)) {
                return v;
            }
        }

        return null;
    }

    /**
     * @param  s A time specification
     * @return   The specified duration in milliseconds
     * @see      #parse(String)
     * @see      #durationOf(Map)
     */
    public static long durationOf(String s) {
        Map<TimeValueConfig, Long> spec = parse(s);
        return durationOf(spec);
    }

    /**
     * @param  s                        An input time specification containing possibly mixed numbers and units - e.g.,
     *                                  {@code 3h10m} to indicate 3 hours and 10 minutes
     * @return                          A {@link Map} specifying for each time unit its count
     * @throws NumberFormatException    If bad numbers found - e.g., negative counts
     * @throws IllegalArgumentException If bad format - e.g., unknown unit
     */
    public static Map<TimeValueConfig, Long> parse(String s) throws IllegalArgumentException {
        if (GenericUtils.isEmpty(s)) {
            return Collections.emptyMap();
        }

        int lastPos = 0;
        Map<TimeValueConfig, Long> spec = new EnumMap<>(TimeValueConfig.class);
        for (int curPos = 0; curPos < s.length(); curPos++) {
            char ch = s.charAt(curPos);
            if ((ch >= '0') && (ch <= '9')) {
                continue;
            }

            if (curPos <= lastPos) {
                throw new IllegalArgumentException("parse(" + s + ") missing count value at index=" + curPos);
            }

            TimeValueConfig c = fromValueChar(ch);
            if (c == null) {
                throw new IllegalArgumentException("parse(" + s + ") unknown time value character: '" + ch + "'");
            }

            String v = s.substring(lastPos, curPos);
            long count = Long.parseLong(v);
            if (count < 0L) {
                throw new IllegalArgumentException("parse(" + s + ") negative count (" + v + ") for " + c.name());
            }

            Long prev = spec.put(c, count);
            if (prev != null) {
                throw new IllegalArgumentException(
                        "parse(" + s + ") " + c.name() + " value re-specified: current=" + count + ", previous=" + prev);
            }

            lastPos = curPos + 1;
            if (lastPos >= s.length()) {
                break;
            }
        }

        if (lastPos < s.length()) {
            String v = s.substring(lastPos);
            long count = Long.parseLong(v);
            if (count < 0L) {
                throw new IllegalArgumentException("parse(" + s + ") negative count (" + v + ") for last component");
            }

            Long prev = spec.put(SECONDS, count);
            if (prev != null) {
                throw new IllegalArgumentException(
                        "parse(" + s + ") last component (" + SECONDS.name() + ") value re-specified: current=" + count
                                                   + ", previous=" + prev);
            }
        }

        return spec;
    }

    /**
     * @param  spec                     The {@link Map} specifying the count for each {@link TimeValueConfig}
     * @return                          The total duration in milliseconds
     * @throws IllegalArgumentException If negative count for a time unit
     */
    public static long durationOf(Map<TimeValueConfig, ? extends Number> spec) throws IllegalArgumentException {
        if (GenericUtils.isEmpty(spec)) {
            return -1L;
        }

        long total = 0L;
        // Cannot use forEach because the total value is not effectively final
        for (Map.Entry<TimeValueConfig, ? extends Number> se : spec.entrySet()) {
            TimeValueConfig v = se.getKey();
            Number c = se.getValue();
            long factor = c.longValue();
            if (factor < 0L) {
                throw new IllegalArgumentException("valueOf(" + spec + ") bad factor (" + c + ") for " + v.name());
            }

            long added = v.getInterval() * factor;
            total += added;
        }

        return total;
    }
}
