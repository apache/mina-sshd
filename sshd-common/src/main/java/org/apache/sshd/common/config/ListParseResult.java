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

import java.util.List;

import org.apache.sshd.common.util.GenericUtils;

/**
 * Used to hold the result of parsing a list of value. Such result contains known and unknown values - which are
 * accessible via the respective {@link #getParsedValues()} and {@link #getUnsupportedValues()} methods. <B>Note:</B>
 * the returned {@link List}s may be un-modifiable, so it is recommended to avoid attempting changing the, returned
 * list(s)
 *
 * @param  <E> Type of list item
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class ListParseResult<E> {
    private final List<E> parsed;
    private final List<String> unsupported;

    protected ListParseResult(List<E> parsed, List<String> unsupported) {
        this.parsed = parsed;
        this.unsupported = unsupported;
    }

    /**
     * @return The {@link List} of successfully parsed value instances in the <U>same order</U> as they were encountered
     *         during parsing
     */
    public final List<E> getParsedValues() {
        return parsed;
    }

    /**
     * @return A {@link List} of unknown/unsupported configuration values for the factories
     */
    public List<String> getUnsupportedValues() {
        return unsupported;
    }

    @Override
    public String toString() {
        return "parsed=" + GenericUtils.join(getParsedValues(), ',')
               + ";unsupported=" + GenericUtils.join(getUnsupportedValues(), ',');
    }
}
