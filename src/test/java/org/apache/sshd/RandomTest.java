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
package org.apache.sshd;

import org.junit.Test;
import org.apache.sshd.common.random.JceRandom;
import org.apache.sshd.common.random.BouncyCastleRandom;
import org.apache.sshd.common.Random;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public class RandomTest {

    @Test
    public void testJce() {
        long t = test(new JceRandom());
        System.out.println("JCE: " + t + " micro");
    }

    @Test
    public void testBc() {
        long t = test(new BouncyCastleRandom());
        System.out.println("BC:  " + t + " micro");
    }

    protected long test(Random random) {
        byte[] bytes = new byte[32];
        long l0 = System.nanoTime();
        for (int i = 0; i < 1000; i++) {
            random.fill(bytes, 8, 16);
        }
        long l1 = System.nanoTime();
        return (l1 - l0) / 1000;
    }
}
