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
package org.apache.sshd.server;

/**
 * System signals definition that the shell can receive.
 *
 * @see ShellFactory.Environment
 */
public interface Signals {

	public static final int SIGHUP = 1;
	public static final int SIGINT = 2;
	public static final int SIGQUIT = 3;
	public static final int SIGILL = 4;
	public static final int SIGTRAP = 5;
	public static final int SIGIOT = 6;
	public static final int SIGBUS = 7;
	public static final int SIGFPE = 8;
	public static final int SIGKILL = 9;
	public static final int SIGUSR1 = 10;
	public static final int SIGSEGV = 11;
	public static final int SIGUSR2 = 12;
	public static final int SIGPIPE = 13;
	public static final int SIGALRM = 14;
	public static final int SIGTERM = 15;
	public static final int SIGSTKFLT = 16;
	public static final int SIGCHLD = 17;
	public static final int SIGCONT = 18;
	public static final int SIGSTOP = 19;
	public static final int SIGTSTP = 20;
	public static final int SIGTTIN = 21;
	public static final int SIGTTOU = 22;
	public static final int SIGURG = 23;
	public static final int SIGXCPU = 24;
	public static final int SIGXFSZ = 25;
	public static final int SIGVTALRM = 26;
	public static final int SIGPROF = 27;
	public static final int SIGWINCH = 28;
	public static final int SIGIO = 29;
	public static final int SIGPWR = 30;

}
