# MCPTT-Wireshark-Dissector
Mission Critical Push To Talk (MCPTT) Wireshark dissector

* Author: Iñigo Ruiz Relloso
* Email:  iruizr7@gmail.com
* Contributors: Mikel Ramos (mikel.ramos@ehu.eus)
* Copyright (c) 2016, Nemergent Initiative http://nemergent.com

This MCPTT dissector is intended to provide supported protocol analyzers with a
better understanding of the MCPTT protocol designed by 3GPP.

This work was made to be conformant to 3GPP TS 24.380 version 13.0.2 Release 13.

The MCPTT dissector by Nemergent Initiative is under the GPLv3 license, please
refer to the LICENSE.txt file for further information.

To obtain more information about the Nemergent developments in the MCPTT field,
or the Next Generation Emergency Services Networks, please don't hesitate to
contact us at http://nemergent.com.

### Currently tested/supported protocol analyzers:

* Wireshark
* Tshark

Installation / Use with Wireshark
---------------------------------

## Permanent install

To add the dissector to your permanent dissector library, you can copy the
mcptt.lua file to the following folder.  

    ~/.wireshark/plugins/mcptt.lua	
	
Note that the `~` (tilde) symbol usually expands into your current user's home
folder in most of the Linux/Mac shells.  
If you intend to use the dissector with another user, just copy it to the
intended user's homologous folder.

Other linux distributions search for wireshark plugins in other system folders.
For example, we have tested other distributions where user plugins should be
placed in the following folder:

    ~/.config/wireshark/plugins/mcptt.lua 
	
Windows users should add the plugin to the following folder:

	%APPDATA%\Wireshark\plugins\mcptt.lua

You can check the specific folder in Help > About Wireshark > Folders > Personal
plugins.

## Occasional use

To use the dissector without having to install the file, an argument can be
supplied to both Wireshark and Tshark as below:

    wireshark -X lua_script:/path/to/mcptt.lua PCAPFILE
    tshark -X lua_script:/path/to/mcptt.lua -r PCAPFILE

**Please note that using this form while already having the dissector installed
in the user's wireshark plugins folder is discouraged and causes errors.**

## RTCP dissection troubleshooting

Is quite common to have some RTCP packets recorded without its correspondent
SIP conversation packets. In this case Wireshark/Tshark does not decode the
packets correctly, displaying them as mere UDP packets.
In this case, the MCPTT does not trigger and the protocol is not parsed.

To force Wireshark to decode them as RTCP, and therefore, let the MCPTT dissector
work on them, do the following:

### Wireshark

Open the contextual menu for the UDP packets and select "Decode As", then, select
`RTCP` from the list.

### Tshark

Use the following switch at the command line:

    tshark -r PCAPFILE -d udp.port==PORT,rtcp

Specifying the used port for the MCPTT or any other filter that is suitable
for you.
