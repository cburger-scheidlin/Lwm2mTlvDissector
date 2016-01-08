Lwm2mTlvDissector
=================
A Post-Dissector for Wireshark that dissects the TLV format specified in OMA's Lwm2m

This repository provides two dissectors, one based on lua for easy testing and one "proper"
C-based wireshark plugin.

Lua Dissector
-------------
You need a wireshark version with lua support installed. This can be checked via
Help -> About Wireshark and then the "Wireshark" tab. Check for "with Lua" in the text.

If you have lua installed, go to the "Folders" tab to identify your "Personal Plugins"
directory. Then simply copy the Lwm2mTlvDissector.lua file into that directory.

C Dissector
-----------
This requires building the plugin with cmake and thus an installed cmake and the wireshark
development support installed.
A simple `mkdir build; cd build; cmake ..; make` should build the plugin 'lwm2mtlv.so'
which can then be copied into the "Personal Plugins" directory.