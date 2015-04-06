package com.npa.emulator;

import java.io.IOException;
import java.util.Calendar;
import java.util.Date;

import org.spongycastle.asn1.ASN1StreamParser;
import org.spongycastle.asn1.DERApplicationSpecific;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTags;

import android.database.Cursor;

import com.npa.androsmex.asn1.CVCertBody;
import com.npa.gui.MainActivity;
import com.npa.tools.Tools;

public class CVCertificateParser {

	CVCertBody certBody;
	
	public CVCertificateParser(byte[] i) throws IllegalArgumentException, IOException {
//	    // built CVCertificate
//		byte[] cert_in = new byte[i.length + 4];
//		System.arraycopy(new byte[] {(byte)0x7f, (byte)0x21, (byte)0x81}, 0, cert_in, 0, 3);
//		System.arraycopy(new byte[] {(byte)i.length}, 0, cert_in, 3, 1);
//		System.arraycopy(i, 0, cert_in, 4, i.length);
		
		

		
		ASN1StreamParser asn1Parser = new ASN1StreamParser(i);
		DERApplicationSpecific body = (DERApplicationSpecific) asn1Parser.readObject();
		
//		
//		DERApplicationSpecific cvcert = (DERApplicationSpecific) asn1Parser.readObject();
//		if (cvcert.getApplicationTag()!=0x21) throw new IllegalArgumentException("Can't find a CV Certificate");
//		
//		ASN1Sequence derCert= (ASN1Sequence)cvcert.getObject(DERTags.SEQUENCE); // Das CV Cerificate ist eine Sequence
//		
//		DERApplicationSpecific body = (DERApplicationSpecific) derCert.getObjectAt(0); //Das erste Objekt des Certificates ist der Cert-Body
		if (body.getApplicationTag()!=0x4E) throw new IllegalArgumentException("Can't find a Body in the CV Certificate");
		
		certBody = new CVCertBody(body);
	}
	
//	public byte getRole() {
//		return certBody.getCHAT().getRole();
//	}
	
	public String getCertificateDescription() throws IOException {	
		
		DERSequence certExtensions = certBody.getExtensions();
		
		byte[] certDescription = ((DERSequence) ((DERApplicationSpecific) certExtensions.getObjectAt(0)).getObject(DERTags.SEQUENCE)).getObjectAt(1).getDERObject().getDEREncoded();

		// object identifier und laengenbyte abschneiden
		byte[] hash = new byte[certDescription.length - 2];
		System.arraycopy(certDescription, 2, hash, 0, hash.length);
		
	    // use db
	    CertificateDescriptionDB db = new CertificateDescriptionDB(MainActivity.ma);
	    String query = Tools.bts(hash);

        Cursor c = db.getWordMatches(query, null);
        //process Cursor and display results
        
        if(c != null)
        	return c.getString(1);
        else
        	return "";
	}
	
	public Date getExpirationDate() {
		return certBody.getExpirationDate();
	}
	
	/**
	 * Ueberprueft, ob das Zertifikat noch aktuell ist
	 */
	public boolean checkExpirationDate() {
		Date expDate = getExpirationDate();
		Date today = Calendar.getInstance().getTime();
		
		return expDate.after(today);
	}

}
