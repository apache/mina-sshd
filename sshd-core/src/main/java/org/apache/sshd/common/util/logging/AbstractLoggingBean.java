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

import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.util.GenericUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Serves as a common base class for the vast majority of classes that require
 * some kind of logging. Facilitates quick and easy replacement of the actual used
 * logger from one framework to another
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractLoggingBean {
    protected final Logger log;
    private final AtomicReference<SimplifiedLog> simplifiedLog = new AtomicReference<>();

    /**
     * Default constructor - creates a logger using the full class name
     */
    protected AbstractLoggingBean() {
        this("");
    }

    /**
     * Create a logger for instances of the same class for which we might
     * want to have a &quot;discriminator&quot; for them
     *
     * @param discriminator The discriminator value - ignored if {@code null}
     * or empty
     */
    protected AbstractLoggingBean(String discriminator) {
        String name = getClass().getName();
        if (GenericUtils.length(discriminator) > 0) {
            name += "[" + discriminator + "]";
        }
        log = LoggerFactory.getLogger(name);
    }

    protected SimplifiedLog getSimplifiedLogger() {
        SimplifiedLog logger;
        synchronized (simplifiedLog) {
            logger = simplifiedLog.get();
            if (logger == null) {
                logger = LoggingUtils.wrap(log);
            }
        }

        return logger;
    }
}
