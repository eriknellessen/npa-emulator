package com.npa.tools;

public class Tools {
	// wandelt String in byte Array um (leerzeichen werden herausgeschnitten)
	public static byte[] stb(String s) {
		s = s.replaceAll(" ", "");
        int len = s.length();
        byte[] data = new byte[len/2];

        for(int i = 0; i < len; i+=2){
            data[i/2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }

        return data;
    }
	
	public static String bts(byte[] byteArray) {
        StringBuilder sb = new StringBuilder();
        for(byte b : byteArray){
            sb.append(String.format("%02x", b&0xff));
        }
        return sb.toString();
	}
	
	public static String bts(byte by) {
		byte[] byteArray = {by};
        StringBuilder sb = new StringBuilder();
        for(byte b : byteArray){
            sb.append(String.format("%02x", b&0xff));
        }
        return sb.toString();
	}
	
}
