# Benchmarks

This is a generalized benchmark runner for Apache MINA sshd JMH benchmarks. It takes a number of command line options to control which benchmarks are run and how.

Without arguments, it runs the full "SFTP upload" benchmark suite against an OpenSSH instance running in a local docker container. The docker engine must be running for this to work. There are command-line arguments to run the benchmarks against any external server; the benchmarks all assume that there is an `upload` directory into which they can write. Command-line argument `--help` lists the available options.

Via the `--run` option, one can control which benchmarks are run.

Benchmarks are run with a warm-up of 4 iterations, and then 10 timed iterations.

