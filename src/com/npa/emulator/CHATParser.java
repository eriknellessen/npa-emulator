package com.npa.emulator;

import java.util.ArrayList;

public class CHATParser {

	byte[] chat;
	// chat als bitmap
	boolean[] bitmap;
	
	// Strings
	String[] CHAT_STRINGS_ = {
	    "Read DG 1 (Document Type)",
	    "Read DG 2 (Issuing State)",
	    "Read DG 3 (Date of Expiry)",
	    "Read DG 4 (Given Names)",
	    "Read DG 5 (Family Names)",
	    "Read DG 6 (Religious/Artistic Name)",
	    "Read DG 7 (Academic Title)",
	    "Read DG 8 (Date of Birth)",
	    "Read DG 9 (Place of Birth)",
	    "Read DG 10 (Nationality)",
	    "Read DG 11 (Sex)",
	    "Read DG 12 (OptionalDataR)",
	    "Read DG 13",
	    "Read DG 14",
	    "Read DG 15",
	    "Read DG 16",
	    "Read DG 17 (Normal Place of Residence)",
	    "Read DG 18 (Community ID)",
	    "Read DG 19 (Residence Permit I)",
	    "Read DG 20 (Residence Permit II)",
	    "Read DG 21 (OptionalDataRW)"
    };
	
	String[] CHAT_STRINGS = {
			"Age Verification",
	    	"Community ID Verification",
	    	"Restricted Identification",
	    	"Privileged Terminal",
	        "CAN allowed",
	        "PIN Management",
	        "Install Certificate",
	        "Install Qualified Certificate",
	        "Read DG 1 (Document Type)",
	        "Read DG 2 (Issuing State)",
	        "Read DG 3 (Date of Expiry)",
	        "Read DG 4 (Given Names)",
	        "Read DG 5 (Family Names)",
	        "Read DG 6 (Religious/Artistic Name)",
	        "Read DG 7 (Academic Title)",
	        "Read DG 8 (Date of Birth)",
	        "Read DG 9 (Place of Birth)",
	        "Read DG 10 (Nationality)",
	        "Read DG 11 (Sex)",
	        "Read DG 12 (OptionalDataR)",
	        "Read DG 13",
	        "Read DG 14",
	        "Read DG 15",
	        "Read DG 16",
	        "Read DG 17 (Normal Place of Residence)",
	        "Read DG 18 (Community ID)",
	        "Read DG 19 (Residence Permit I)",
	        "Read DG 20 (Residence Permit II)",
	        "Read DG 21 (OptionalDataRW)",
	        "RFU",
	        "RFU",
	        "RFU",
	        "RFU",
	        "Write DG 21 (OptionalDataRW)",
	        "Write DG 20 (Residence Permit I)",
	        "Write DG 19 (Residence Permit II)",
	        "Write DG 18 (Community ID)",
	        "Write DG 17 (Normal Place of Residence)"			
	};
	
	String[] ROLE_STRINGS = {
		"CVCA",
		"DV (official domestic)",
		"DV (non-official / foreign)",
		"Authentication Terminal"
	};
	
	public CHATParser(byte[] chat) {
		this.chat = chat;
		if(chat != null) {
			bitmap = byteArrayToBitArray(chat);
			// reverse bitmap
			for (int i = 0; i < bitmap.length / 2; i++) {
				  boolean temp = bitmap[i];
				  bitmap[i] = bitmap[bitmap.length - 1 - i];
				  bitmap[bitmap.length - 1 - i] = temp;
			}
		}
	}
	
	public String getRole() {
		// CVCA

		if(bitmap[0] && bitmap[1]) {
			return ROLE_STRINGS[0];
		}
		if(bitmap[0] && !bitmap[1]) {
			return ROLE_STRINGS[1];
		}
		if(!bitmap[0] && bitmap[1]) {
			return ROLE_STRINGS[2];
		}
		else {
			return ROLE_STRINGS[3];
		}
		
	}
	
	// Schreibrechte
	public String[] getWriteAccess() {	
		ArrayList<String> list = new ArrayList<String>();
		for(int i = 2; i < 7; i++) {
			if(bitmap[i]) {
				list.add(CHAT_STRINGS[i]);
			}
		}
		return list.toArray(new String[list.size()]);
	}
	
	// Leserechte
	public String[] getReadAccess() {	
		ArrayList<String> list = new ArrayList<String>();
		for(int i = 7; i < 28; i++) {
			if(bitmap[i]) {
				list.add(CHAT_STRINGS[i]);
			}
		}
		return list.toArray(new String[list.size()]);
	}
	
	// Special Functions
	public String[] getSpecialFunctions() {	
		ArrayList<String> list = new ArrayList<String>();
		for(int i = 28; i < CHAT_STRINGS.length; i++) {
			if(bitmap[i]) {
				list.add(CHAT_STRINGS[i]);
			}
		}
		return list.toArray(new String[list.size()]);
	}
	

	// Wandelt byte array in boolean array um
	private boolean[] byteArrayToBitArray(byte[] bytes) {
		boolean[] bits = new boolean[bytes.length * 8];
		for (int i = 0; i < bytes.length * 8; i++) {
		if ((bytes[i / 8] & (1 << (7 - (i % 8)))) > 0)
			bits[i] = true;
		}
			
		return bits;
	}

}
