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

package org.apache.sshd.cli;

import java.io.PrintStream;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Objects;
import java.util.logging.Level;

import org.apache.sshd.common.util.logging.SimplifiedLog;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CliLogger implements SimplifiedLog {
    public static final DateFormat LOG_TIME_FORMATTER = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss,SSS");

    protected final Level threshold;
    protected final PrintStream logStream;

    public CliLogger(Level threshold, PrintStream logStream) {
        this.threshold = threshold;
        this.logStream = logStream;
    }

    @Override
    public boolean isEnabledLevel(Level level) {
        return SimplifiedLog.isLoggable(level, threshold);
    }

    @Override
    public void log(Level level, Object msg, Throwable err) {
        if (!isEnabledLevel(level)) {
            return;
        }

        Date now = new Date();
        String time;
        synchronized (LOG_TIME_FORMATTER) {
            time = LOG_TIME_FORMATTER.format(now);
        }
        logStream.append(time)
                .append(' ').append(level.getName())
                .append(' ').append(Thread.currentThread().getName())
                .append(' ').append(Objects.toString(msg))
                .println();
        if (err != null) {
            err.printStackTrace(logStream);
        }
    }
}
