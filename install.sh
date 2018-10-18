#!/bin/bash
FOLDER=~/.config/wireshark/plugins
if [ ! -d "$FOLDER" ]; then
    mkdir -p $FOLDER
fi
cp -f *.lua $FOLDER
