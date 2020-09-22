#!/bin/bash

# Tx
./x86_64-native-linuxapp-gcc/io -l 12 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func tx --ingress-ring ring:tx:0:0 --egress-port 0 --egress-queue 0 &
sleep 1
./x86_64-native-linuxapp-gcc/io -l 14 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func tx --ingress-ring ring:tx:0:1 --egress-port 0 --egress-queue 1 &
sleep 1
./x86_64-native-linuxapp-gcc/io -l 16 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func tx --ingress-ring ring:tx:0:2 --egress-port 0 --egress-queue 2 &
sleep 1
./x86_64-native-linuxapp-gcc/io -l 18 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func tx --ingress-ring ring:tx:0:3 --egress-port 0 --egress-queue 3 &
sleep 1
./x86_64-native-linuxapp-gcc/io -l 20 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func tx --ingress-ring ring:tx:0:4 --egress-port 0 --egress-queue 4 &
sleep 3

# Rx
./x86_64-native-linuxapp-gcc/io -l 2 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func rx --ingress-port 0 --ingress-queue 0 --egress-ring ring:tx:0:0 &
sleep 1

./x86_64-native-linuxapp-gcc/io -l 4 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func rx --ingress-port 0 --ingress-queue 1 --egress-ring ring:tx:0:1 &
sleep 1

./x86_64-native-linuxapp-gcc/io -l 6 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func rx --ingress-port 0 --ingress-queue 2 --egress-ring ring:tx:0:2 &
sleep 1

./x86_64-native-linuxapp-gcc/io -l 8 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func rx --ingress-port 0 --ingress-queue 3 --egress-ring ring:tx:0:3 &
sleep 1

./x86_64-native-linuxapp-gcc/io -l 10 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func rx --ingress-port 0 --ingress-queue 4 --egress-ring ring:tx:0:4 &
sleep 1

#./x86_64-native-linuxapp-gcc/io -l 12 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func rx --ingress-port 0 --ingress-queue 5 --egress-ring ring:tx:0:5 &
#sleep 1

#./x86_64-native-linuxapp-gcc/io -l 14 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func rx --ingress-port 0 --ingress-queue 6 --egress-ring ring:tx:0:0 &
#sleep 1

#./x86_64-native-linuxapp-gcc/io -l 16 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func rx --ingress-port 0 --ingress-queue 7 --egress-ring ring:tx:0:1 &
#sleep 1

#./x86_64-native-linuxapp-gcc/io -l 18 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func rx --ingress-port 0 --ingress-queue 8 --egress-ring ring:tx:0:2 &
#sleep 1

#./x86_64-native-linuxapp-gcc/io -l 20 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func rx --ingress-port 0 --ingress-queue 9 --egress-ring ring:tx:0:3 &
#sleep 1

#./x86_64-native-linuxapp-gcc/io -l 22 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func rx --ingress-port 0 --ingress-queue 10 --egress-ring ring:tx:0:4 &
#sleep 1

#./x86_64-native-linuxapp-gcc/io -l 2 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func rx --ingress-port 0 --ingress-queue 11 --egress-ring ring:tx:0:0 &
#sleep 1

#./x86_64-native-linuxapp-gcc/io -l 4 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func rx --ingress-port 0 --ingress-queue 12 --egress-ring ring:tx:0:1 &
#sleep 1

#./x86_64-native-linuxapp-gcc/io -l 6 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func rx --ingress-port 0 --ingress-queue 13 --egress-ring ring:tx:0:2 &
#sleep 1

#./x86_64-native-linuxapp-gcc/io -l 8 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func rx --ingress-port 0 --ingress-queue 14 --egress-ring ring:tx:0:3 &
#sleep 1

#./x86_64-native-linuxapp-gcc/io -l 10 -n 4 --proc-type auto -w 05:00.0 -w 05:00.1  -- --func rx --ingress-port 0 --ingress-queue 15 --egress-ring ring:tx:0:4 &
#sleep 1

