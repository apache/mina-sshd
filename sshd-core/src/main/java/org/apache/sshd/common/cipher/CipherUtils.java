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
import org.apache.sshd.common.Factory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CipherUtils {
    /**
     * Checks if the provided cipher factory instance generates a cipher
     * that is supported by the JCE
     * @param f The cipher factory instance
     * @return The {@link Exception} that the {@link Cipher#init(org.apache.sshd.common.Cipher.Mode, byte[], byte[])}
     * call has thrown - {@code null} if successful (i.e., cipher supported)
     * @see <A HREF="http://www.oracle.com/technetwork/java/javase/downloads/">Java Cryptography Extension (JCE)</A>
     */
    public static Exception checkSupported(Factory<? extends Cipher> f) {
        return checkSupported(f.create());
    }

    /**
     * Checks if the provided cipher is supported by the JCE
     * @param c The {@link Cipher} to be checked
     * @return The {@link Exception} that the {@link Cipher#init(org.apache.sshd.common.Cipher.Mode, byte[], byte[])}
     * call has thrown - {@code null} if successful (i.e., cipher supported)
     * @see <A HREF="http://www.oracle.com/technetwork/java/javase/downloads/">Java Cryptography Extension (JCE)</A>
     */
    public static Exception checkSupported(Cipher c) {
        try {
            byte[] key=new byte[c.getBlockSize()];
            byte[] iv=new byte[c.getIVSize()];
            c.init(Cipher.Mode.Encrypt, key, iv);
            return null;
        } catch(Exception e) {
            return e;
        }
    }
}
