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

import java.util.regex.Pattern;

import org.apache.sshd.common.util.GenericUtils;

/**
 * Represents a pattern definition in the <U>known_hosts</U> file
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see <A HREF="https://en.wikibooks.org/wiki/OpenSSH/Client_Configuration_Files#About_the_Contents_of_the_known_hosts_Files">
 * OpenSSH cookbook - About the Contents of the known hosts Files</A>
 */
public class HostPatternValue {
    private Pattern pattern;
    private int port;
    private boolean negated;

    public HostPatternValue() {
        super();
    }

    public HostPatternValue(Pattern pattern, boolean negated) {
        this(pattern, 0, negated);
    }

    public HostPatternValue(Pattern pattern, int port, boolean negated) {
        this.pattern = pattern;
        this.port = port;
        this.negated = negated;
    }

    public Pattern getPattern() {
        return pattern;
    }

    public void setPattern(Pattern pattern) {
        this.pattern = pattern;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public boolean isNegated() {
        return negated;
    }

    public void setNegated(boolean negated) {
        this.negated = negated;
    }

    @Override
    public String toString() {
        Pattern p = getPattern();
        String purePattern = (p == null) ? null : p.pattern();
        StringBuilder sb = new StringBuilder(GenericUtils.length(purePattern) + Short.SIZE);
        if (isNegated()) {
            sb.append(HostPatternsHolder.NEGATION_CHAR_PATTERN);
        }

        int portValue = getPort();
        if (portValue > 0) {
            sb.append(HostPatternsHolder.NON_STANDARD_PORT_PATTERN_ENCLOSURE_START_DELIM);
        }
        sb.append(purePattern);
        if (portValue > 0) {
            sb.append(HostPatternsHolder.NON_STANDARD_PORT_PATTERN_ENCLOSURE_END_DELIM);
            sb.append(HostPatternsHolder.PORT_VALUE_DELIMITER);
            sb.append(portValue);
        }

        return sb.toString();
    }
}
