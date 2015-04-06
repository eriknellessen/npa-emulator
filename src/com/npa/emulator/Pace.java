package com.npa.emulator;

import com.npa.androsmex.asn1.SecurityInfos;
import com.npa.androsmex.iso7816.CommandAPDU;
import com.npa.androsmex.iso7816.ResponseAPDU;
import com.npa.androsmex.pace.PaceOperator;

public class Pace {
	PaceOperator p;	
	String ef_cardaccess_string = "31 81 C1 30 0D 06 08 04 00 7F 00 07 02 02 02 02 01 02 30 12 06 0A 04 00 7F 00 07 02 02 03 02 02 02 01 02 02 01 48 30 12 06 0A 04 00 7F 00 07 02 02 04 02 02 02 01 02 02 01 0D 30 1C 06 09 04 00 7F 00 07 02 02 03 02 30 0C 06 07 04 00 7F 00 07 01 02 02 01 0D 02 01 48 30 2A 06 08 04 00 7F 00 07 02 02 06 16 1E 68 74 74 70 3A 2F 2F 62 73 69 2E 62 75 6E 64 2E 64 65 2F 63 69 66 2F 6E 70 61 2E 78 6D 6C 30 3E 06 08 04 00 7F 00 07 02 02 08 31 32 30 12 06 0A 04 00 7F 00 07 02 02 03 02 02 02 01 02 02 01 49 30 1C 06 09 04 00 7F 00 07 02 02 03 02 30 0C 06 07 04 00 7F 00 07 01 02 02 01 0D 02 01 49 00";
//	String ef_cardaccess_string = "3181c6300d060804007f00070202020201023012060a04007f000702020302020201020201013012060a04007f0007020204020202010202010D301c060904007f000702020302300c060704007f0007010202010D020101302f060804007f0007020206162368747470733a2f2f7777772e686a702d636f6e73756c74696e672e636f6d2f686f6d65303e060804007f000702020831323012060a04007f00070202030202020102020102301c060904007f000702020302300c060704007f0007010202010D020102";

	
	public Pace(NPAEmulator npa, String pin) {
		p = new PaceOperator(npa);

		SecurityInfos si = p.getSecurityInfosFromCardAccess(ef_cardaccess_string);	
		p.setAuthTemplate(si.getPaceInfoList().get(0));	
		p.initialize(pin);	
	}
	
	/**
	 * fuehrt PACE durch bzw. verarbeitet die fuer PACE relevanten APDUs 
	 */
	public ResponseAPDU performPace(CommandAPDU cmd) {
		byte[] data = p.performPace(cmd.getData());

		return new ResponseAPDU(data, new byte[] {(byte)0x90 ,(byte)0x00});
		
	}
}
