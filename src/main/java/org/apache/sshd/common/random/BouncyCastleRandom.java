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
package org.apache.sshd.common.random;

import java.security.SecureRandom;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Random;
import org.bouncycastle.crypto.prng.RandomGenerator;
import org.bouncycastle.crypto.prng.VMPCRandomGenerator;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public class BouncyCastleRandom implements Random {

    public static class Factory implements NamedFactory<Random> {

        public String getName() {
            return "bouncycastle";
        }

        public Random create() {
            return new BouncyCastleRandom();
        }

    }

    private final RandomGenerator random;

    public BouncyCastleRandom() {
        this.random = new VMPCRandomGenerator();
        byte[] seed = new SecureRandom().generateSeed(8);
        this.random.addSeedMaterial(seed);
    }

    public void fill(byte[] bytes, int start, int len) {
        this.random.nextBytes(bytes, start, len);
    }
}
