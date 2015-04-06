package com.npa.emulator;

import java.io.IOException;

import android.content.Context;
import android.content.Intent;
import android.util.Log;

import com.npa.androsmex.iso7816.CommandAPDU;
import com.npa.androsmex.iso7816.ResponseAPDU;
import com.npa.tools.Tools;

public class TA {

	private Context ctx;

	public TA(Context ctx) {
		this.ctx = ctx;
	}
	
	/**
	 * veraerbeitet die fuer die TA relevanten APDUs und schickt die relevanten Informationen aus den Zertifikaten an die GUI
	 */
	public ResponseAPDU performTA(CommandAPDU cmd) {
		// zertifikat erhalten
		if(cmd.getINS() == 0x2A && cmd.getP1() == 0x00 && cmd.getP2() == 0xBE) {
			byte[] cert = cmd.getData();
		    
			// dv cert
			//cert = Tools.stb("7F 4E 81 A0 5F 29 01 00 42 0E 44 45 43 56 43 41 65 49 44 30 30 31 30 33 7F 49 4F 06 0A 04 00 7F 00 07 02 02 02 02 03 86 41 04 7E 1C 99 65 42 9E FA 63 73 74 B5 DA 9F 8A D6 43 32 8F 32 15 EB AB 6F A8 CB CA 3C 06 25 C8 B3 12 4D E1 43 7A 62 35 C9 DC CD EC 1D 51 10 DB B4 08 F1 BF 9E 1A EA B6 31 84 31 04 7F 82 38 7A 22 3E 5F 20 10 44 45 44 56 65 49 44 44 50 53 54 30 30 30 33 31 7F 4C 12 06 09 04 00 7F 00 07 03 01 02 02 53 05 40 05 13 FF 87 5F 25 06 01 04 00 07 02 08 5F 24 06 01 04 01 00 02 06 5F 37 40 15 00 FE F4 73 94 60 96 9F DD A0 E1 F3 12 E2 66 F7 17 39 E7 CB 79 33 92 55 65 7A C9 46 05 9C DE 6C 8B B7 5F 38 1C D5 B1 66 47 91 EB CA 28 EC 13 6F 14 FC F3 5D 10 96 EA 81 A9 69 A4 08 82 E0 0E");
			
			// terminal cert
			cert = Tools.stb("7F4E8201025F2901004210444544566549444450535430303033317F494F060A04007F000702020202038641047E4B55B93BF0A071981D29EF9BE6D5D6AB2AC4045E63A2200E37F7BB13CE566B48B46AFFA44B7FAFC51083C1E41A0C6BF75629EE5A4C27F608C5B3547FC2AC785F20104445414B444253454C425330303533387F4C12060904007F0007030102025305000513FB075F25060104000801045F2406010400080105655E732D060904007F00070301030180205ADF58DE040ACB3EFC7462606456F1D00A4520B70F8A9C11CD9C1459DF98C715732D060904007F00070301030280205D5B44A9775D806FAD201A45FCAA489F88FC66B5A9589BF2E991D3E8F13F3B0D5F374032470C38D39E24E361FD1006997D4BA64991F10F6C89EEFAED95D8CA7F36F9E085C9C8D96255643D9AF62B221140C7B649E1584D0796A021076677D8D100D65C");

		    
			if(cert[0] == (byte)0x7f && cert[1] == (byte)0x4e) {
				try {									
					// parse CVCertificate
					CVCertificateParser parser = new CVCertificateParser(cert);
					StringBuilder sb = new StringBuilder();
					sb.append("<h2> CERTIFICATE: </h2>");
					sb.append("<h3>Certificate Description: </h3> ");	
					
					sb.append(parser.getCertificateDescription());
					sb.append("<br />");
					
					sb.append("<h3>Expiration Date: </h3>"); 
					sb.append(parser.getExpirationDate());
					if(parser.checkExpirationDate())
						sb.append(" (unexpired)");
					else
						sb.append(" (expired!)");
					sb.append("<br />");
					Log.i("TA", sb.toString());
					sendCertInformations(sb.toString());
					
				} catch (IllegalArgumentException e) {System.out.println(e.getMessage());} catch (IOException e) {System.out.println(e.getMessage());}
			}
		}
		
		return new ResponseAPDU(new byte[] {(byte)0x90 ,(byte)0x00});
	}

	/**
	 * sendet die Zertifikatinformationen an die GUI
	 */
	private void sendCertInformations(String certInformations) {
		// log an MainActivity senden
		Intent i = new Intent("CHAT_UPDATED");
		i.putExtra("CERT", certInformations);
		ctx.sendBroadcast(i);
	}

}
