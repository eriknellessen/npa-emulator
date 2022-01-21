package com.npa.emulator;

import com.npa.androsmex.iso7816.CommandAPDU;



public class MSESetAT {
	

    
	// Daten der APDU, die CHAT enthaelt 
	byte[] data;

	public MSESetAT(byte[] apdu) {
		CommandAPDU capdu = new CommandAPDU(apdu);
		data = capdu.getData();
	}
	
	public MSESetAT(CommandAPDU capdu) {
		data = capdu.getData();
	}
	
	public CHATParser getCHAT() {
		// find tag 7F 4C
		byte[] tag = {(byte)0x7f, (byte)0x4c};

		for (int i = 0; i < data.length; i++) {
			// tag gefunden
			if(data[i] == tag[0] && data[i+1] == tag[1]) {
				int length = data[i+2];
				int startByte = i+3;
				
				byte[] chat = new byte[length];
				System.arraycopy(data, startByte, chat ,0 , length);

				return new CHATParser(chat);
			}
		}
		return null;
	}	


	

}
