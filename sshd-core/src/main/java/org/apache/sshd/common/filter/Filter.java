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
package org.apache.sshd.common.filter;

/**
 * A message filter belonging to a {@link FilterChain}.
 */
public interface Filter extends Owned<FilterChain> {

    /**
     * Retrieves the filter's {@link InputHandler}.
     *
     * @return the {@link InputHandler} or code {@code null} if this filter is an output-only filter
     */
    InputHandler in();

    /**
     * Retrieves the filter's {@link OutputHandler}.
     *
     * @return the {@link OutputHandler} or code {@code null} if this filter is an input-only filter
     */
    OutputHandler out();
}
