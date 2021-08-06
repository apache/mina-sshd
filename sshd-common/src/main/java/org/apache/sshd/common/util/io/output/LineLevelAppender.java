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

package org.apache.sshd.common.util.io.output;

import java.io.Closeable;
import java.io.IOException;
import java.util.Objects;
import java.util.function.BooleanSupplier;

import org.apache.sshd.common.util.io.LineDataConsumer;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface LineLevelAppender extends LineDataConsumer, Closeable {
    /**
     * A typical line length used in many textual standards
     */
    int TYPICAL_LINE_LENGTH = 80;

    LineLevelAppender EMPTY = new LineLevelAppender() {
        @Override
        public void writeLineData(CharSequence lineData) throws IOException {
            // ignored
        }

        @Override
        public boolean isWriteEnabled() {
            return false;
        }

        @Override
        public void close() throws IOException {
            // do nothing
        }

        @Override
        public String toString() {
            return "EMPTY";
        }
    };

    /**
     * @return {@code true} if OK to accumulate data in work buffer
     */
    boolean isWriteEnabled();

    @Override
    default void consume(CharSequence lineData) throws IOException {
        writeLineData(lineData);
    }

    /**
     * Called by the implementation once end-of-line is detected.
     *
     * @param  lineData    The &quot;pure&quot; line data - excluding any CR/LF(s).
     * @throws IOException If failed to write the data
     */
    void writeLineData(CharSequence lineData) throws IOException;

    static LineLevelAppender wrap(Appendable appendable) {
        return wrap(appendable, () -> true);
    }

    static LineLevelAppender wrap(Appendable appendable, BooleanSupplier writeEnabled) {
        Objects.requireNonNull(appendable, "No appendable to wrap");
        return new LineLevelAppender() {
            /**
             * indicates whether a line has been written
             */
            private boolean writtenFirstLine;

            @Override
            public void close() throws IOException {
                if (appendable instanceof Closeable) {
                    ((Closeable) appendable).close();
                }
            }

            @Override
            public void writeLineData(CharSequence lineData) throws IOException {
                if (writtenFirstLine) {
                    appendable.append(System.lineSeparator());
                }

                appendable.append(lineData);
                writtenFirstLine = true;
            }

            @Override
            public boolean isWriteEnabled() {
                return writeEnabled.getAsBoolean();
            }

            @Override
            public String toString() {
                return appendable.toString();
            }
        };
    }
}
