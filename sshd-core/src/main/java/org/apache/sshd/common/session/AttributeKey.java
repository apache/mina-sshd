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
package org.apache.sshd.common.session;

/**
 * Type safe key for storage within the user attributes of {@link AbstractSession}.
 * Typically it is used as a static variable that is shared between the producer
 * and the consumer. To further restrict access the setting or getting it from
 * the ServerSession you can add static get and set methods, e.g:
 * 
 * private static final AttributeKey<MyValue> MY_KEY = new AttributeKey<MyValue>();
 *
 * public static MyValue getMyValue(ServerSession s) {
 *   return s.getAttribute(MY_KEY);
 * }
 *
 * private void setMyValye(ServerSession s, MyValue value) {
 *   s.setAttribute(MY_KEY, value);
 * }
 *
 * @param T type of value stored in the attribute.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class AttributeKey<T> {
}
