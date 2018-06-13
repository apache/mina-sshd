@echo off
rem
rem
rem    Licensed to the Apache Software Foundation (ASF) under one or more
rem    contributor license agreements.  See the NOTICE file distributed with
rem    this work for additional information regarding copyright ownership.
rem    The ASF licenses this file to You under the Apache License, Version 2.0
rem    (the "License"); you may not use this file except in compliance with
rem    the License.  You may obtain a copy of the License at
rem
rem       http://www.apache.org/licenses/LICENSE-2.0
rem
rem    Unless required by applicable law or agreed to in writing, software
rem    distributed under the License is distributed on an "AS IS" BASIS,
rem    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
rem    See the License for the specific language governing permissions and
rem    limitations under the License.
rem
rem

if not "%ECHO%" == "" echo %ECHO%

setlocal
set DIRNAME=%~dp0%
set PROGNAME=%~nx0%
set ARGS=%*

title sshd

goto BEGIN

:warn
    echo %PROGNAME%: %*
goto :EOF

:BEGIN

rem # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if not "%SSHD_HOME%" == "" (
    call :warn Ignoring predefined value for SSHD_HOME
)
set SSHD_HOME=%DIRNAME%..
if not exist "%SSHD_HOME%" (
    call :warn SSHD_HOME is not valid: %SSHD_HOME%
    goto END
)

set DEFAULT_JAVA_OPTS=-server -Xmx512M -Dcom.sun.management.jmxremote
set DEFAULT_JAVA_DEBUG_OPTS=-Xdebug -Xnoagent -Djava.compiler=NONE -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=5005

rem Support for loading native libraries
set PATH=%PATH%;%SSHD_HOME%\lib

rem Setup the Java Virtual Machine
if not "%JAVA%" == "" goto :Check_JAVA_END
    set JAVA=java
    if "%JAVA_HOME%" == "" call :warn JAVA_HOME not set; results may vary
    if not "%JAVA_HOME%" == "" set JAVA=%JAVA_HOME%\bin\java
    if not exist "%JAVA_HOME%" (
        call :warn JAVA_HOME is not valid: "%JAVA_HOME%"
        goto END
    )
:Check_JAVA_END

if "%JAVA_OPTS%" == "" set JAVA_OPTS=%DEFAULT_JAVA_OPTS%

if "%SSHD_DEBUG%" == "" goto :SSHD_DEBUG_END
    rem Use the defaults if JAVA_DEBUG_OPTS was not set
    if "%JAVA_DEBUG_OPTS%" == "" set JAVA_DEBUG_OPTS=%DEFAULT_JAVA_DEBUG_OPTS%

    set "JAVA_OPTS=%JAVA_DEBUG_OPTS% %JAVA_OPTS%"
    call :warn Enabling Java debug options: %JAVA_DEBUG_OPTS%
:SSHD_DEBUG_END

rem Setup the classpath
set CLASSPATH=%LOCAL_CLASSPATH%
pushd "%SSHD_HOME%\lib"
for %%G in (*.*) do call:APPEND_TO_CLASSPATH %%G
popd
goto CLASSPATH_END

: APPEND_TO_CLASSPATH
set filename=%~1
set suffix=%filename:~-4%
if %suffix% equ .jar set CLASSPATH=%CLASSPATH%;%SSHD_HOME%\lib\%filename%
goto :EOF

:CLASSPATH_END

SET ARGS=%1 %2 %3 %4 %5 %6 %7 %8
rem Execute the Java Virtual Machine
cd %SSHD_HOME%
"%JAVA%" %JAVA_OPTS% %OPTS% -classpath "%CLASSPATH%" -Dsshd.home="%SSHD_HOME%" org.apache.sshd.cli.server.SshServerMain %ARGS%

rem # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

:END

endlocal

if not "%PAUSE%" == "" pause

:END_NO_PAUSE

