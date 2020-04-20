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
package org.apache.sshd.util.test;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class JSchLogger implements Logger {
    private final org.slf4j.Logger log = LoggerFactory.getLogger(JSch.class);

    public JSchLogger() {
        super();
    }

    @Override
    public boolean isEnabled(int level) {
        switch (level) {
            case INFO: // INFO is too "chatty" so we map it to debug
            case DEBUG:
                return log.isDebugEnabled();
            case WARN:
                return log.isWarnEnabled();
            case ERROR:
                return log.isErrorEnabled();
            case FATAL:
                return log.isErrorEnabled();
            default:
                return false;
        }
    }

    @Override
    public void log(int level, String message) {
        switch (level) {
            case INFO: // INFO is too "chatty" so we map it to debug
            case DEBUG:
                log.debug(message);
                break;
            case WARN:
                log.warn(message);
                break;
            case ERROR:
            case FATAL:
                log.error(message);
                break;
            default:
                log.error("[LEVEL=" + level + "]: " + message);
        }
    }

    public static void init() {
        JSch.setLogger(new JSchLogger());
    }
}
