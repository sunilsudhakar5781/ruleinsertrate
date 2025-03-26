# About
This is a sample application to profile time taken for 64k rule (default value) to be inserted to a pipe from same core, different cores with and without batching.

# How to build
meson build && ninja -C build

# How to run
./build/rule_insert_rate -a <interface1>,dv_flow_en=2 -a <interface2>,dv_flow_en=2
ex: ./build/rule_insert_rate -a 03:00.0,dv_flow_en=2 -a 03:00.1,dv_flow_en=2
