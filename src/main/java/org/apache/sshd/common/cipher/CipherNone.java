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
package org.apache.sshd.common.cipher;

import org.apache.sshd.common.Cipher;
import org.apache.sshd.common.NamedFactory;

/**
 * Represents a no-op cipher.
 * This cipher can not really be used during authentication and should only
 * be used after, so that authentication remains secured, but not the remaining
 * of the exchanges.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public class CipherNone implements Cipher {

    /**
     * Named factory for the no-op Cipher
     */
    public static class Factory implements NamedFactory<Cipher> {
        public String getName() {
            return "none";
        }
        public Cipher create() {
            return new CipherNone();
        }
    }

    public int getIVSize() {
        return 8;
    }

    public int getBlockSize() {
        return 16;
    }

    public void init(Mode mode, byte[] bytes, byte[] bytes1) throws Exception {
    }

    public void update(byte[] input, int inputOffset, int inputLen) throws Exception {
    }

}
