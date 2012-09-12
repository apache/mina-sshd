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
 * ARCFOUR128 cipher
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ARCFOUR128 extends BaseCipher {

    /**
     * Named factory for AES128CTR Cipher
     */
    public static class Factory implements NamedFactory<Cipher> {
        public String getName() {
            return "arcfour128";
        }
        public Cipher create() {
            return new ARCFOUR128();
        }
    }

    public ARCFOUR128() {
        super(8, 16, "ARCFOUR", "RC4");
    }

    @Override
    public void init(Mode mode, byte[] key, byte[] iv) throws Exception {
        super.init(mode, key, iv);
        try {
            byte[] foo = new byte[1];
            for (int i = 0; i < 1536; i++) {
                cipher.update(foo, 0, 1, foo, 0);
            }
        } catch (Exception e) {
            cipher = null;
            throw e;
        }
    }

}
