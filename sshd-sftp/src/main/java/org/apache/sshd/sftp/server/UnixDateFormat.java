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
package org.apache.sshd.sftp.server;

import java.nio.file.attribute.FileTime;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.List;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class UnixDateFormat {

    /**
     * A {@link List} of <U>short</U> months names where Jan=0, Feb=1, etc.
     */
    public static final List<String> MONTHS = Collections.unmodifiableList(
            Arrays.asList(
                    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"));

    /**
     * Six months duration in msec.
     */
    public static final long SIX_MONTHS = 183L * 24L * 60L * 60L * 1000L;

    private UnixDateFormat() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    /**
     * Get unix style date string.
     *
     * @param  time The {@link FileTime} to format - ignored if {@code null}
     * @return      The formatted date string
     * @see         #getUnixDate(long)
     */
    public static String getUnixDate(FileTime time) {
        return getUnixDate((time != null) ? time.toMillis() : -1L);
    }

    public static String getUnixDate(long millis) {
        if (millis < 0L) {
            return "------------";
        }

        StringBuilder sb = new StringBuilder(16);
        Calendar cal = new GregorianCalendar();
        cal.setTimeInMillis(millis);

        // month
        sb.append(MONTHS.get(cal.get(Calendar.MONTH)));
        sb.append(' ');

        // day
        int day = cal.get(Calendar.DATE);
        if (day < 10) {
            sb.append(' ');
        }
        sb.append(day);
        sb.append(' ');

        long nowTime = System.currentTimeMillis();
        if (Math.abs(nowTime - millis) > SIX_MONTHS) {

            // year
            int year = cal.get(Calendar.YEAR);
            sb.append(' ');
            sb.append(year);
        } else {
            // hour
            int hh = cal.get(Calendar.HOUR_OF_DAY);
            if (hh < 10) {
                sb.append('0');
            }
            sb.append(hh);
            sb.append(':');

            // minute
            int mm = cal.get(Calendar.MINUTE);
            if (mm < 10) {
                sb.append('0');
            }
            sb.append(mm);
        }

        return sb.toString();
    }
}
