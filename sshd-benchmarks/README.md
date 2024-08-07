# JMH Benchmarks

This project provides a few JMH benchmarks. It is not part of the Apache MINA sshd binary distribution.

For details about the benchmarks, see the individual READMEs.

Note that benchmarking or timing individual SSH or SFTP operations is difficult because there are always
at least two servers and a network connection in between involved. Some tests run an SSH peer in a local
docker container. The network connection is fast and has a very low latency, but the machine executing
the benchmarks also executes the docker container, which may skew timings. If tests are run against an
external SSH peer on some other machine, the network may be slower and/or have a higher latency, which
again may give unusable timings. Moreover, if the network is a general-purpose network, other traffic may
influence timings, and if there are firewalls and/or proxies in between, getting meaningful timings may
be even harder.

Other processes running on the machine executing the benchmarks may also influence timings. In
particular, suspend automatic backups during benchmarking, and try to avoid interference from virus
scanners. Shut down messaging programs (Teams and the like, but also E-Mail programs), maybe even Web
Browsers or programs that may suddenly check for available updates). Don't do other things on the
machine while the benchmark runs; even scrolling in some other window will skew timings.
