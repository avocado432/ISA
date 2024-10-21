# ISA - project
## Monitoring of DHCP traffic
Author: Tereza Lapčíková, xlapci03
20.11.2023

### Description
Program used for monitoring of the maximum number of hosts,
allocated addresses and utilization of chosen ip prefixes.

### How to build the program:
make

### How to run the program:
./dhcp-stats [-r &lt;filename&gt;] [-i &lt;interface-name&lt;] [&lt;ip-prefix&gt; [ &lt;ip-prefix&gt; [ ... ] ]

### Submitted files
dhcp-stats.cpp
Makefile
dhcp-stats.1
manual.pdf
README.md