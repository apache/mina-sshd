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
package org.apache.sshd.server.kex;

import org.apache.sshd.common.KeyExchange;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.kex.DH;
import org.apache.sshd.common.kex.DHGroupData;

public class DHG1 extends AbstractDHGServer {

    public static class Factory implements NamedFactory<KeyExchange> {

        public String getName() {
            return "diffie-hellman-group1-sha1";
        }

        public KeyExchange create() {
            return new DHG1();
        }

    }

    protected void initDH(DH dh) {
        dh.setG(DHGroupData.G);
        dh.setP(DHGroupData.P_1);
    }

}
