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
package org.apache.sshd.common.util.logging;

import java.util.logging.Level;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SimplifiedLog {
    /**
     * An &quot;empty&quot; {@link SimplifiedLog} that does nothing
     */
    SimplifiedLog EMPTY = new SimplifiedLog() {
        @Override
        public boolean isEnabledLevel(Level level) {
            return false;
        }

        @Override
        public void log(Level level, Object message, Throwable t) {
            // ignored
        }

        @Override
        public String toString() {
            return "EMPTY";
        }
    };

    default boolean isErrorEnabled() {
        return isEnabledLevel(Level.SEVERE);
    }

    default void error(String msg) {
        error(msg, null);
    }

    default void error(String msg, Throwable err) {
        log(Level.SEVERE, msg, err);
    }

    default boolean isWarnEnabled() {
        return isEnabledLevel(Level.WARNING);
    }

    default void warn(String msg) {
        warn(msg, null);
    }

    default void warn(String msg, Throwable err) {
        log(Level.WARNING, msg, err);
    }

    default boolean isInfoEnabled() {
        return isEnabledLevel(Level.INFO);
    }

    default void info(String msg) {
        info(msg, null);
    }

    default void info(String msg, Throwable err) {
        log(Level.INFO, msg, err);
    }

    default boolean isDebugEnabled() {
        return isEnabledLevel(Level.FINE);
    }

    default void debug(String msg) {
        debug(msg, null);
    }

    default void debug(String msg, Throwable err) {
        log(Level.FINE, msg, err);
    }

    default boolean isTraceEnabled() {
        return isEnabledLevel(Level.FINER);
    }

    default void trace(String msg) {
        trace(msg, null);
    }

    default void trace(String msg, Throwable err) {
        log(Level.FINER, msg, err);
    }

    boolean isEnabledLevel(Level level);

    default void log(Level level, Object message) {
        log(level, message, null);
    }

    void log(Level level, Object message, Throwable t);

    static boolean isErrorEnabled(Level level) {
        return isLoggable(level, Level.SEVERE);
    }

    static boolean isWarnEnabled(Level level) {
        return isLoggable(level, Level.WARNING);
    }

    static boolean isInfoEnabled(Level level) {
        return isLoggable(level, Level.INFO);
    }

    static boolean isDebugEnabled(Level level) {
        return isLoggable(level, Level.FINE);
    }

    static boolean isTraceEnabled(Level level) {
        return isLoggable(level, Level.FINER);
    }

    /**
     * Verifies if the given level is above the required threshold for logging.
     *
     * @param  level     The {@link Level} to evaluate
     * @param  threshold The threshold {@link Level}
     * @return           {@code true} if the evaluated level is above the required threshold.
     *                   <P>
     *                   <B>Note(s):</B>
     *                   </P>
     *                   <UL>
     *                   <LI>
     *                   <P>
     *                   If either argument is {@code null} then result is {@code false}.
     *                   </P>
     *                   </LI>
     *
     *                   <LI>
     *                   <P>
     *                   If the evaluated level is {@link Level#OFF} then result is {@code false} regardless of the
     *                   threshold.
     *                   </P>
     *                   </LI>
     *
     *                   <LI>
     *                   <P>
     *                   If the threshold is {@link Level#ALL} and the evaluated level is <U>not</U> {@link Level#OFF}
     *                   the result is {@code true}.
     *                   </P>
     *                   </LI>
     *
     *                   <LI>
     *                   <P>
     *                   Otherwise, the evaluated level {@link Level#intValue()} must be greater or equal to the
     *                   threshold.
     *                   </P>
     *                   </LI>
     *                   </UL>
     */
    static boolean isLoggable(Level level, Level threshold) {
        if ((level == null) || (threshold == null)) {
            return false;
        } else if (Level.OFF.equals(level) || Level.OFF.equals(threshold)) {
            return false;
        } else if (Level.ALL.equals(threshold)) {
            return true;
        } else {
            return level.intValue() >= threshold.intValue();
        }
    }
}
