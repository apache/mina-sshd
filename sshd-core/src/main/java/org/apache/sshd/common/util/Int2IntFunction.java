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
@FunctionalInterface
public interface Int2IntFunction extends IntUnaryOperator {

    /**
     * An {@link Int2IntFunction} that returns same value as input
     */
    Int2IntFunction IDENTITY = value -> value;

    @Override
    default int applyAsInt(int operand) {
        return apply(operand);
    }

    /**
     * @param value Argument
     * @return Function result
     */
    int apply(int value);

    static Int2IntFunction sub(int delta) {
        return add(0 - delta);
    }

    static Int2IntFunction add(int delta) {
        if (delta == 0) {
            return IDENTITY;
        } else {
            return value -> value + delta;
        }
    }

    static Int2IntFunction mul(int factor) {
        if (factor == 1) {
            return IDENTITY;
        } else {
            return value -> value * factor;
        }
    }

    static Int2IntFunction div(int factor) {
        if (factor == 1) {
            return IDENTITY;
        } else {
            ValidateUtils.checkTrue(factor != 0, "Zero division factor");
            return value -> value / factor;
        }
    }
}
