#!/usr/bin/env python3
"""R1-C7: run-all-psu.sh (R1-C6, unmodified) calls plot_loadtest.py of its working directory at the end of each run.
run-R1C7.sh runs run-all-psu.sh with k6-psu-c7 as working directory => this file replaces the C6 plotting:
the C7 runs (burst, hops) do not draw the C6 load-test figures; the C7 analysis is done separately."""
print("   (R1-C7) C6 load-test figures skipped for the C7 run")
