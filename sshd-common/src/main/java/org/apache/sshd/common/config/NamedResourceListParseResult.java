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

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.util.GenericUtils;

/**
 * @param  <R> Type of result {@link NamedResource}
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class NamedResourceListParseResult<R extends NamedResource> extends ListParseResult<R> {
    protected NamedResourceListParseResult(List<R> parsed, List<String> unsupported) {
        super(parsed, unsupported);
    }

    /**
     * @return The {@link List} of successfully parsed {@link NamedResource} instances in the <U>same order</U> as they
     *         were encountered during parsing
     */
    public final List<R> getParsedResources() {
        return getParsedValues();
    }

    /**
     * @return A {@link List} of unknown/unsupported configuration values for the resources
     */
    public List<String> getUnsupportedResources() {
        return getUnsupportedValues();
    }

    @Override
    public String toString() {
        return "parsed=" + NamedResource.getNames(getParsedResources())
               + ";unknown=" + GenericUtils.join(getUnsupportedResources(), ',');
    }
}
