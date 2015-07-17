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
package org.apache.sshd.client.auth;

/**
 * Interface used by the ssh client to communicate with the end user.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see <a href="https://www.ietf.org/rfc/rfc4256.txt">RFC 4256</A>
 */
public interface UserInteraction {

    /**
     * Displays the welcome banner to the user.
     *
     * @param banner The welcome banner
     */
    void welcome(String banner);

    /**
     * @param destination The session identifier
     * @param name        The interaction name (may be empty)
     * @param instruction The instruction (may be empty)
     * @param lang        The language for the data (may be empty)
     * @param prompt      The prompts to be displayed (may be empty)
     * @param echo        For each prompt whether to echo the user's response
     * @return The replies - <B>Note:</B> the protocol states that the number
     * of replies should be <U>exactly</U> the same as the number of prompts,
     * however we do not enforce it since it is defined as the <U>server's</U>
     * job to check and manage this violation
     */
    String[] interactive(String destination,
                         String name,
                         String instruction,
                         String lang,
                         String[] prompt,
                         boolean[] echo);
}
