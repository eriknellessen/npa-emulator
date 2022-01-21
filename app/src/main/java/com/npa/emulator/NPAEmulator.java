package com.npa.emulator;

import java.util.Arrays;
import java.util.Random;

import android.content.Context;
import android.content.Intent;
import android.util.Log;

import com.npa.androsmex.iso7816.CommandAPDU;
import com.npa.androsmex.iso7816.ResponseAPDU;
import com.npa.androsmex.iso7816.SecureMessaging;
import com.npa.androsmex.iso7816.SecureMessagingException;
import com.npa.tools.Tools;


public class NPAEmulator{
	private Context ctx;
	
	private Pace pace = null;
	private TA ta = null;
	private SecureMessaging sm = null;
	private boolean sm_activ = false;
	
	
	// aktuelles Kommando / Antwort
	private CommandAPDU cmd;
	private ResponseAPDU response;
	
	// Strings
//	private String response_cardAccess = "3181 c630 0d06 0804 007f 0007 0202 02020102 3012 060a 0400 7f00 0702 0203 0102 0201 0202 0101 3012 060a 0400 7f00 07020204 0102 0201 0202 0100 301c 0609 04007f00 0702 0203 0130 0c06 0704 007f 00070102 0201 0002 0101 302f 0608 0400 7f000702 0206 1623 6874 7470 733a 2f2f 7777772e 686a 702d 636f 6e73 756c 7469 6e672e63 6f6d 2f68 6f6d 6530 3e06 0804 007f0007 0202 0831 3230 1206 0a04 007f 00070202 0301 0202 0102 0201 0230 1c06 0904007f 0007 0202 0301 300c 0607 0400 7f000701 0202 0100 0201 02";
	private String response_cardAccess = "31 81 C1 30 0D 06 08 04 00 7F 00 07 02 02 02 02 01 02 30 12 06 0A 04 00 7F 00 07 02 02 03 02 02 02 01 02 02 01 48 30 12 06 0A 04 00 7F 00 07 02 02 04 02 02 02 01 02 02 01 0D 30 1C 06 09 04 00 7F 00 07 02 02 03 02 30 0C 06 07 04 00 7F 00 07 01 02 02 01 0D 02 01 48 30 2A 06 08 04 00 7F 00 07 02 02 06 16 1E 68 74 74 70 3A 2F 2F 62 73 69 2E 62 75 6E 64 2E 64 65 2F 63 69 66 2F 6E 70 61 2E 78 6D 6C 30 3E 06 08 04 00 7F 00 07 02 02 08 31 32 30 12 06 0A 04 00 7F 00 07 02 02 03 02 02 02 01 02 02 01 49 30 1C 06 09 04 00 7F 00 07 02 02 03 02 30 0C 06 07 04 00 7F 00 07 01 02 02 01 0D 02 01 49 00";
	
	public NPAEmulator(Context ctx, String pin) {
		this.ctx = ctx;
		pace = new Pace(this, pin);
		ta = new TA(ctx);
		ta.performTA(new CommandAPDU(Tools.stb("00 2a00be")));

	}

	/**
	 * verarbeitet eingehende Command APDUs
	 * @param Command APDU
	 * @return Response APDU
	 */
	public byte[] processCommandApdu(byte[] capdu) {
		this.cmd = new CommandAPDU(capdu);
		
    	// unwrap capdu, wenn secure messaging aktiv ist
    	if(sm != null && cmd.getCLA() == 0x0C) {
    	    sm_activ = true;
    		try {
				cmd = sm.unwrap_capdu(cmd);
			} catch (SecureMessagingException e) {
				Log.e("SM", e.getMessage());
			}
    	}
    	else
    		sm_activ = false;
    	
		// APDU loggen
	    logAPDU("CAPDU", cmd.getBytes());

		switch(cmd.getINS()) {
		case(0x86):
			// pace wird durchgefuehrt
			response = pace.performPace(cmd);
			break;
		case(0x2A):
			// TA durchfuehren
	    	response = ta.performTA(cmd);
			break;
		case(0xB0):
			// read binary (card_access wird abgefragt)
			response = readBinary();
			break;
		case(0xA4):
			// select file
			response = selectFile();
			//response = new ResponseAPDU(new byte[] {(byte)0x6A, (byte)0x82});
			break;
		case(0x22):
			if(cmd.getP1() == 0xC1 && cmd.getP2() == 0xA4) {
				processMSESetAT();	
			}
			response = unknownCommand();
			break;
		case(0x84):
			// zufallszahl wird angefordert
			response = askRandom();
//			response = new ResponseAPDU(Tools.stb("6900"));
			break;
		default:
			response = unknownCommand();
		}
    	
		
		// APDU loggen
	    logAPDU("RAPDU", response.getBytes());

	    
	    // wrap Response APDU
    	if(sm != null && sm_activ) {
    		try {
    			response = sm.wrap_rapdu(response);
			} catch (SecureMessagingException e) {}
    	}
    	
		return response.getBytes();
	}
	
	/**
	 * verarbeitet eingehendes MSE Set AT
	 * sendet Informationen aus dem CHAT an die GUI
	 */
	private void processMSESetAT() {
		MSESetAT m = new MSESetAT(cmd);
		
		if(m.getCHAT() != null) {
			CHATParser chat = m.getCHAT();
			
			StringBuilder sb = new StringBuilder();
			
			// Rolle
			sb.append("<h3>Role:</h3>");
			sb.append(chat.getRole() + "<br />");
			
			// Write Access
			sb.append("<h3>Write Access:</h3>");
			for(String a : chat.getWriteAccess()) {
				sb.append(a + "<br />");
			}
			
			// Read Access
			sb.append("<h3>Read Access:</h3>");
			for(String a : chat.getReadAccess()) {
				sb.append(a + "<br />");
			}
			
			// Special functions
			sb.append("<h3>Special Functions:</h3>");
			for(String a : chat.getSpecialFunctions()) {
				sb.append(a + "<br />");
			}
			
			
			// Acces Rights an MainActivity senden
			Intent i = new Intent("CHAT_UPDATED");
			i.putExtra("CHAT", sb.toString());
			ctx.sendBroadcast(i);
		}
		else {
			Log.i("NPA-Emulator", "MSE Set AT fehlerhaft!");
		}
		
	}
	
	/**
	 * ASK RANDOM
	 * Request a random number from the smart card.
	 */
	private ResponseAPDU askRandom() {
		int length = cmd.getNe();
		byte[] data = new byte[length];
		new Random().nextBytes(data);
		
		return new ResponseAPDU(data, new byte[] {(byte)0x90, (byte)0x00});
	}

	/**
	 * Unknown Command
	 * Einige Command APDUs werden behandelt.
	 */
	private ResponseAPDU unknownCommand() {
		if(cmd.getINS() == 0xCA) {
			return new ResponseAPDU(new byte[] {(byte)0x6D, (byte)0x00});
		}
		if(cmd.getINS() == 0x9A) {
			return new ResponseAPDU(new byte[] {(byte)0x6E, (byte)0x00});
		}
		return new ResponseAPDU(new byte[] {(byte)0x90, (byte)0x00});
	}
	
	/**
	 * SELECT
	 * Select a file.
	 */
	private ResponseAPDU selectFile() {
		ResponseAPDU rapdu = null;
		byte[] fid = cmd.getData();
		if(Arrays.equals(fid, Tools.stb("2f00")) || Arrays.equals(fid, Tools.stb("2f01"))) {
			// ef_dir
			rapdu = new ResponseAPDU(Tools.stb("6A 82"));
		}
		else if(Arrays.equals(fid, Tools.stb("3d00"))) {
			// mf
			rapdu = new ResponseAPDU(Tools.stb("9000"));
		}
		else {
			rapdu = new ResponseAPDU(Tools.stb("9000"));
		}
		return rapdu;
	}
	
	/**
	 * READ BINARY
	 * Read from a file with a transparent structure.
	 */
	private ResponseAPDU readBinary() {
		
		// erstelle data: card_access
		byte[] card_access = Tools.stb(response_cardAccess);
		

		
		// berechne offset 
		int offset;
		// bit8 in P1 ist nicht gesetzt
		if(cmd.getP1() < 128) {
			offset = cmd.getP1()*256 + cmd.getP2();
			
		}
		// hack fuer short EF identifier
		else if(cmd.getP1() == 156) {
			offset = 0;
		}
		// bit8 in P1 ist gesetzt (es werden nur Nullen ausgegeben
		else {	
			offset = card_access.length;
		}
		// hack fuer ausweisapp
		if (cmd.getP1() == 0x04 && cmd.getP2() == 00) {
			return new ResponseAPDU(new byte[] {(byte)0x6B, (byte)0x00});
		}
		if(cmd.getP1() == 0x03 && cmd.getP2() == 0x7C) {
			return new ResponseAPDU(Tools.stb("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0000 00 00 00 00 00 00 00 00 00 00 0062 82"));
		}
		
		
		
		// berechne datenlaenge
		int length = card_access.length;
		if(cmd.getNe() > 0){
			length = cmd.getNe();
		}
		// beschraenkung auf apdus mit le < 256, da kein extended APDU support
		if(length > 250) {
			length = 250;
		}
		
		// berechne datenfeld
		byte[] rapdu_data = new byte[length];
		                             
		for(int i = offset; i < card_access.length && i-offset < rapdu_data.length; i++) {
			rapdu_data[i-offset] = card_access[i];
		}
		
		// berechne Statuscode: 9000
		byte[] sw = Tools.stb("9000");
		
		// berechne Response APDU
		ResponseAPDU rapdu = new ResponseAPDU(rapdu_data, sw);

		return rapdu;
	}
	
	/**
	 * Logt APDUs und schickt das Log an die GUI
	 * @param Typ der APDU (CAPDU, RAPDU)
	 * @param APDU
	 */
	private void logAPDU(String type, byte[] apdu) {
		Log.i("NPa-Emulator" , type + ": " + Tools.bts(apdu));
		
	    StringBuilder sb = new StringBuilder();
	    for(byte b : apdu){
	    	sb.append(String.format("%02x", b&0xff));
	    	sb.append(" ");
	    }
	    String str;
	    if(type.equals("CAPDU")) {
	    	str = "<font color=#000080>" + sb.toString() + "</font><br />";
	    }
	    else if(type.equals("RAPDU")){
	    	str = "<font color=#006400>" + sb.toString() + "</font><br />";
	    }
	    else
	    	return;

		// log an MainActivity senden
		Intent i = new Intent("CHAT_UPDATED");
		i.putExtra("LOG", str);
		ctx.sendBroadcast(i);
	}
	
	/**
	 * Setzt Secure Messaging
	 * @param Secure Messaging Objekt
	 */
	public void setSMObject(SecureMessaging sm) {
		Log.i("SM", "Set Secure Messaging!");
		this.sm = sm;
		
	}
	
}
