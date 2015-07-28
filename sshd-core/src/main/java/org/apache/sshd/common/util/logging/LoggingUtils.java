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

package org.apache.sshd.common.util.logging;

import java.util.Objects;
import java.util.logging.Level;

import org.slf4j.Logger;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class LoggingUtils {

    private LoggingUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    /**
     * Verifies if the given level is above the required threshold for logging.
     *
     * @param level     The {@link Level} to evaluate
     * @param threshold The threshold {@link Level}
     * @return {@code true} if the evaluated level is above the required
     * threshold.
     * <P>
     * <B>Note(s):</B>
     * </P>
     * <UL>
     * <LI><P>
     * If either argument is {@code null} then result is {@code false}.
     * </P></LI>
     *
     * <LI><P>
     * If the evaluated level is {@link Level#OFF} then result is {@code false}
     * regardless of the threshold.
     * </P></LI>
     *
     * <LI><P>
     * If the threshold is {@link Level#ALL} and the evaluated level is
     * <U>not</U> {@link Level#OFF} the result is {@code true}.
     * </P></LI>
     *
     * <LI><P>
     * Otherwise, the evaluated level {@link Level#intValue()} must be
     * greater or equal to the threshold.
     * </P></LI>
     * </UL>
     */
    public static boolean isLoggable(Level level, Level threshold) {
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

    public static SimplifiedLog wrap(final Logger logger) {
        if (logger == null) {
            return SimplifiedLog.EMPTY;
        } else {
            return new AbstractSimplifiedLog() {
                @Override
                public void log(Level level, Object message, Throwable t) {
                    if (isEnabled(level)) {
                        logMessage(logger, level, message, t);
                    }

                }

                @Override
                public boolean isEnabled(Level level) {
                    return isLoggable(logger, level);
                }
            };
        }
    }

    // NOTE: assume that level enabled has been checked !!!
    public static void logMessage(Logger logger, Level level, Object message, Throwable t) {
        if ((logger == null) || (level == null) || Level.OFF.equals(level)) {
            return;
        } else if (Level.SEVERE.equals(level)) {
            logger.error(Objects.toString(message), t);
        } else if (Level.WARNING.equals(level)) {
            logger.warn(Objects.toString(message), t);
        } else if (Level.INFO.equals(level) || Level.ALL.equals(level)) {
            logger.info(Objects.toString(message), t);
        } else if (Level.CONFIG.equals(level) || Level.FINE.equals(level)) {
            logger.debug(Objects.toString(message), t);
        } else {
            logger.trace(Objects.toString(message), t);
        }
    }

    /**
     * @param logger The {@link Logger} instance - ignored if {@code null}
     * @param level  The validate log {@link Level} - ignored if {@code null}
     * @return <P>{@code true} if the level is enabled for the logger. The
     * mapping of the level to the logger is as follows:</P>
     * <UL>
     * <LI>{@link Level#OFF} always returns {@code false}</LI>
     * <LI>{@link Level#SEVERE} returns {@link Logger#isErrorEnabled()}</LI>
     * <LI>{@link Level#WARNING} returns {@link Logger#isWarnEnabled()}</LI>
     * <LI>{@link Level#INFO} and {@link Level#ALL} returns {@link Logger#isInfoEnabled()}</LI>
     * <LI>{@link Level#CONFIG} and {@link Level#FINE} returns {@link Logger#isDebugEnabled()}</LI>
     * <LI>All other levels return {@link Logger#isTraceEnabled()}</LI>
     * </UL>
     */
    public static boolean isLoggable(Logger logger, Level level) {
        if ((logger == null) || (level == null) || Level.OFF.equals(level)) {
            return false;
        } else if (Level.SEVERE.equals(level)) {
            return logger.isErrorEnabled();
        } else if (Level.WARNING.equals(level)) {
            return logger.isWarnEnabled();
        } else if (Level.INFO.equals(level) || Level.ALL.equals(level)) {
            return logger.isInfoEnabled();
        } else if (Level.CONFIG.equals(level) || Level.FINE.equals(level)) {
            return logger.isDebugEnabled();
        } else {
            return logger.isTraceEnabled();
        }
    }
}
