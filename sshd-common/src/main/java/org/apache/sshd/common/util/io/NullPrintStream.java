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

package org.apache.sshd.common.util.io;

import java.io.PrintStream;
import java.util.Locale;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class NullPrintStream extends PrintStream {
    public NullPrintStream() {
        super(new NullOutputStream());
    }

    @Override
    public void write(int b) {
        // ignored
    }

    @Override
    public void write(byte[] buf, int off, int len) {
        // ignored
    }

    @Override
    public void print(boolean b) {
        // ignored
    }

    @Override
    public void print(char c) {
        append(c);
    }

    @Override
    public void print(int i) {
        print((long) i);
    }

    @Override
    public void print(long l) {
        // ignored
    }

    @Override
    public void print(float f) {
        print((double) f);
    }

    @Override
    public void print(double d) {
        // ignored
    }

    @Override
    public void print(char[] s) {
        // ignored
    }

    @Override
    public void print(String s) {
        // ignored
    }

    @Override
    public void print(Object obj) {
        // ignored
    }

    @Override
    public void println() {
        // ignored
    }

    @Override
    public void println(boolean x) {
        // ignored
    }

    @Override
    public void println(char x) {
        // ignored
    }

    @Override
    public void println(int x) {
        // ignored
    }

    @Override
    public void println(long x) {
        // ignored
    }

    @Override
    public void println(float x) {
        // ignored
    }

    @Override
    public void println(double x) {
        // ignored
    }

    @Override
    public void println(char[] x) {
        // ignored
    }

    @Override
    public void println(String x) {
        // ignored
    }

    @Override
    public void println(Object x) {
        // ignored
    }

    @Override
    public PrintStream printf(String format, Object... args) {
        return printf(Locale.getDefault(), format, args);
    }

    @Override
    public PrintStream printf(Locale l, String format, Object... args) {
        return format(l, format, args);
    }

    @Override
    public PrintStream format(String format, Object... args) {
        return format(Locale.getDefault(), format, args);
    }

    @Override
    public PrintStream format(Locale l, String format, Object... args) {
        return this;
    }

    @Override
    public PrintStream append(CharSequence csq) {
        return append(csq, 0, csq.length());
    }

    @Override
    public PrintStream append(CharSequence csq, int start, int end) {
        return this;
    }

    @Override
    public PrintStream append(char c) {
        return this;
    }
}
