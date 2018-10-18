# MCX (MCPTT, MCVideo, MCData) Wireshark-Dissector
MCX Wireshark dissector

* Author: Iñigo Ruiz Relloso
* Email:  iruizr7@gmail.com
* Contributors: Mikel Ramos (mikel.ramos@ehu.eus), Iñigo García (inigo.garcia@nemergent-solutions.com)
* Copyright (c) 2018, Nemergent Initiative http://nemergent.com

This MCX dissector is intended to provide supported protocol analyzers with a
better understanding of the (MCPTT, MCVideo, MCData) protocols designed by 3GPP.

This work was made to be conformant to 3GPP TS 24.380 version 13.3.0 Release 13.

In June 2018 MCVideo Release 14 features were added according to 3GPP TS 24.581 version 14.4.0.
In July 2018 Several changes were made to accommodate future MC-Services like MCData and better integration of MCVideo.

The MCX dissector by Nemergent Initiative is under the GPLv3 license, please
refer to the LICENSE.txt file for further information.

To obtain more information about the Nemergent developments in the MCPTT field,
or the Next Generation Emergency Services Networks, please don't hesitate to
contact us at http://nemergent.com.

### Currently tested/supported protocol analyzers:

* Wireshark (v2.2.1 or later)
* Tshark

Installation / Use with Wireshark
---------------------------------

## Permanent install

An automated installer is included in the form of file `install.sh`. This script installs the MCX Dissector to the 
`~/.config/wireshark/plugins` folder, which seems to be the folder used by most recent wireshark versions.
If your distribution uses another folder, you can guess wireshark plugin directories by launching Wireshark, and clicking
through `Help > About > Folders > Personal Configuration`.

To install it in Windows, execute the included `install.ps1` PowerShell script, which does the same procedure as the linux script.

In order to install it manually, just copy all the `.lua` files into the folder Wireshark denominates as "Personal Config Folder" + '/plugins'
, and update `mcptt.lua` and `mcvideo.lua` files accordingly. (On line 30)

## Upgrade

To upgrade current MCX Dissector installation, just re-run `install.sh`/`install.ps1` or overwrite all of the `.lua` files in your installation
folder, and do not forget to update again the paths in `mcptt.lua` and `mcvideo.lua` files (Line 30).


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

### MCVideo specific tips

To filter the three protocol names of MCVideo at the same time:

Click on:
- Analyze > Display Filter Macros > Add Filter (+ symbol)

Then set the name to: MCVD
and the text to: mcvideo_0 || mcvideo_1 || mcvideo_2

Click ok to finish.

To use the macro, type the following at the filter bar: ${MCVD}
