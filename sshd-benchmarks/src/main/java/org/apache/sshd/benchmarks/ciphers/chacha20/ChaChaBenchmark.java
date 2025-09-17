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
package org.apache.sshd.benchmarks.ciphers.chacha20;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.cipher.ChaCha20Cipher;
import org.apache.sshd.common.cipher.ChaCha20CipherFactory;
import org.apache.sshd.common.cipher.Cipher;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

public final class ChaChaBenchmark {

    private ChaChaBenchmark() {
        super();
    }

    @State(Scope.Benchmark)
    public static class CipherBenchmark {

        private static final int SIZE = 32 * 1024;

        private static final Random RND = new SecureRandom();

        private ChaCha20Cipher cipher;
        private Cipher fromFactory;

        private byte[] a;

        public CipherBenchmark() {
            super();
        }

        @Setup(Level.Trial)
        public void setup() throws Exception {
            cipher = new ChaCha20Cipher();
            byte[] key = new byte[cipher.getKdfSize()];
            byte[] iv = new byte[cipher.getIVSize()];
            RND.nextBytes(key);
            iv[iv.length - 1] = 42;
            cipher.init(Cipher.Mode.Encrypt, key, iv);
            fromFactory = ChaCha20CipherFactory.INSTANCE.get();
            if (cipher.getClass().equals(fromFactory.getClass())) {
                throw new IllegalStateException("Ciphers are equal; benchmarking for comparison makes no sense.");
            }
            fromFactory.init(Cipher.Mode.Encrypt, key, iv);
            setupData();
            encrypt();
            byte[] old = Arrays.copyOf(a, a.length);
            setupData();
            encryptFromFactory();
            if (!Arrays.equals(old, a)) {
                throw new IllegalStateException("Encryption error");
            }
        }

        @Setup(Level.Iteration)
        public void setupData() {
            a = new byte[SIZE + 512];
            for (int i = 0; i < SIZE; i++) {
                a[i] = (byte) (i & 0xff);
            }
        }

        @Benchmark
        @Warmup(iterations = 4)
        @Measurement(iterations = 10)
        @BenchmarkMode(Mode.AverageTime)
        @OutputTimeUnit(TimeUnit.NANOSECONDS)
        public void encryptFromFactory() throws Exception {
            fromFactory.updateAAD(a, 0, 4);
            fromFactory.update(a, 4, SIZE);
        }

        @Benchmark
        @Warmup(iterations = 4)
        @Measurement(iterations = 10)
        @BenchmarkMode(Mode.AverageTime)
        @OutputTimeUnit(TimeUnit.NANOSECONDS)
        public void encrypt() throws Exception {
            cipher.updateAAD(a, 0, 4);
            cipher.update(a, 4, SIZE);
        }

    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(ChaChaBenchmark.class.getSimpleName() + '.' + CipherBenchmark.class.getSimpleName()) //
                .forks(1) //
                .threads(1) //
                .build();
        new Runner(opt).run();
    }
}
