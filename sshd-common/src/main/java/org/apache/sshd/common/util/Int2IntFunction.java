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

package org.apache.sshd.common.util;

import java.util.function.IntUnaryOperator;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class Int2IntFunction {
    private Int2IntFunction() {
        throw new UnsupportedOperationException("No instance");
    }

    public static IntUnaryOperator sub(int delta) {
        return add(0 - delta);
    }

    public static IntUnaryOperator add(int delta) {
        if (delta == 0) {
            return IntUnaryOperator.identity();
        } else {
            return value -> value + delta;
        }
    }

    public static IntUnaryOperator mul(int factor) {
        if (factor == 0) {
            return constant(0);
        } else if (factor == 1) {
            return IntUnaryOperator.identity();
        } else {
            return value -> value * factor;
        }
    }

    public static IntUnaryOperator constant(int v) {
        return value -> v;
    }

    public static IntUnaryOperator div(int factor) {
        if (factor == 1) {
            return IntUnaryOperator.identity();
        } else {
            ValidateUtils.checkTrue(factor != 0, "Zero division factor");
            return value -> value / factor;
        }
    }
}
