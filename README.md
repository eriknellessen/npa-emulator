# npa-emulator
The npa emulator is part of the bachelor thesis "Prüfung von öffentlichen eID-Terminals mit einem Android-Smartphone"

It is a partly emulation of the German ID card (neuer Personalausweis) on an Android device with NFC support to check a terminal and prevent skimming.

The npa emulator contains some modified code from the project [androsmex](https://code.google.com/p/androsmex/) (to use the protocol PACE for the card and not for the terminal). Androsmex is an implementation of the PACE protocol for Android phones.

The current state of the thesis is available as [PDF](src/docs/bachelorthesis.pdf)

**This version of npa-emulator has been changed to be buildable via gradle and as an android library. For the original state of the source code see https://gitlab.com/eriknellessen/npa-emulator/-/tags/original-version-by-ole-richter**

[![Build Status](https://gitlab.com/eriknellessen/npa-emulator/badges/master/pipeline.svg)](https://gitlab.com/eriknellessen/npa-emulator/-/pipelines?ref=master)
