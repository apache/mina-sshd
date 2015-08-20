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
    SimplifiedLog EMPTY = new AbstractSimplifiedLog() {
        @Override
        public boolean isEnabled(Level level) {
            return false;
        }

        @Override
        public void log(Level level, Object message, Throwable t) {
            return;
        }

        @Override
        public String toString() {
            return "EMPTY";
        }
    };

    boolean isEnabled(Level level);

    void log(Level level, Object message);

    void log(Level level, Object message, Throwable t);
}
