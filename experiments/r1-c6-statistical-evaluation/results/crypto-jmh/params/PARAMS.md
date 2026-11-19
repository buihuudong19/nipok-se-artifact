# JMH parameters (read from the result JSON files)

| Step | Benchmarks | Mode | Forks | Warmup | Measurement | Threads | JMH | JVM | JVM args |
|---|---|---|---|---|---|---|---|---|---|
| main | 20 | avgt | 10 | 8 × 1 s | 10 × 1 s | 1 | 1.36 | OpenJDK 64-Bit Server VM 24+36 | --enable-native-access=ALL-UNNAMED --enable-native-access=ALL-UNNAMED --sun-misc-unsafe-memory-access=allow |
| main | 20 | avgt | 10 | 8 × 1 s | 10 × 1 s | 1 | 1.36 | OpenJDK 64-Bit Server VM 24+36 | --enable-native-access=ALL-UNNAMED |
| fbc-ab (avgt) | 2 | avgt | 10 | 8 × 1 s | 10 × 1 s | 1 | 1.36 | OpenJDK 64-Bit Server VM 24+36 | --enable-native-access=ALL-UNNAMED |
| fbc-ab (thrpt) | 2 | thrpt | 10 | 8 × 1 s | 10 × 1 s | 1 | 1.36 | OpenJDK 64-Bit Server VM 24+36 | --enable-native-access=ALL-UNNAMED |
| fbc-ab (sample) | 2 | sample | 10 | 8 × 1 s | 10 × 1 s | 1 | 1.36 | OpenJDK 64-Bit Server VM 24+36 | --enable-native-access=ALL-UNNAMED |
| argon2id-sensitivity | 13 | avgt | 10 | 8 × 1 s | 10 × 1 s | 1 | 1.36 | OpenJDK 64-Bit Server VM 24+36 | --enable-native-access=ALL-UNNAMED |
| jvm-control G1 | 5 | avgt | 2 | 8 × 1 s | 10 × 1 s | 1 | 1.36 | OpenJDK 64-Bit Server VM 24+36-jvmci-b01 | -XX:ThreadPriorityPolicy=1 -XX:+UnlockExperimentalVMOptions -XX:+EnableJVMCIProduct -XX:-UnlockExperimentalVMOptions --enable-native-access=ALL-UNNAMED --enable-native-access=ALL-UNNAMED --sun-misc-unsafe-memory-access=allow |
| jvm-control G1 | 5 | avgt | 2 | 8 × 1 s | 10 × 1 s | 1 | 1.36 | OpenJDK 64-Bit Server VM 24+36-jvmci-b01 | -XX:ThreadPriorityPolicy=1 -XX:+UnlockExperimentalVMOptions -XX:+EnableJVMCIProduct -XX:-UnlockExperimentalVMOptions --enable-native-access=ALL-UNNAMED |
| jvm-control T1 | 5 | avgt | 2 | 8 × 1 s | 10 × 1 s | 1 | 1.36 | OpenJDK 64-Bit Server VM 24+36 | --enable-native-access=ALL-UNNAMED --enable-native-access=ALL-UNNAMED --sun-misc-unsafe-memory-access=allow |
| jvm-control T1 | 5 | avgt | 2 | 8 × 1 s | 10 × 1 s | 1 | 1.36 | OpenJDK 64-Bit Server VM 24+36 | --enable-native-access=ALL-UNNAMED |
| jvm-control T2 | 5 | avgt | 2 | 8 × 1 s | 10 × 1 s | 1 | 1.36 | OpenJDK 64-Bit Server VM 24+36 | --enable-native-access=ALL-UNNAMED --enable-native-access=ALL-UNNAMED --sun-misc-unsafe-memory-access=allow |
| jvm-control T2 | 5 | avgt | 2 | 8 × 1 s | 10 × 1 s | 1 | 1.36 | OpenJDK 64-Bit Server VM 24+36 | --enable-native-access=ALL-UNNAMED |
| jvm-control G2 | 5 | avgt | 2 | 8 × 1 s | 10 × 1 s | 1 | 1.36 | OpenJDK 64-Bit Server VM 24+36-jvmci-b01 | -XX:ThreadPriorityPolicy=1 -XX:+UnlockExperimentalVMOptions -XX:+EnableJVMCIProduct -XX:-UnlockExperimentalVMOptions --enable-native-access=ALL-UNNAMED --enable-native-access=ALL-UNNAMED --sun-misc-unsafe-memory-access=allow |
| jvm-control G2 | 5 | avgt | 2 | 8 × 1 s | 10 × 1 s | 1 | 1.36 | OpenJDK 64-Bit Server VM 24+36-jvmci-b01 | -XX:ThreadPriorityPolicy=1 -XX:+UnlockExperimentalVMOptions -XX:+EnableJVMCIProduct -XX:-UnlockExperimentalVMOptions --enable-native-access=ALL-UNNAMED |

Raw parameter files of the harness (wrapper, variables passed in, jar md5): jmh/params/ of the raw data (*.params.txt, README.txt, jmh-jar.md5, jmh-jar.build.txt); environment of each step: jmh/<step>/env.txt.

