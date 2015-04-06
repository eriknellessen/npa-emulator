package com.npa.androsmex.pace;

import static com.npa.androsmex.asn1.BSIObjectIdentifiers.id_PACE_DH_GM;
import static com.npa.androsmex.asn1.BSIObjectIdentifiers.id_PACE_DH_GM_3DES_CBC_CBC;
import static com.npa.androsmex.asn1.BSIObjectIdentifiers.id_PACE_DH_GM_AES_CBC_CMAC_128;
import static com.npa.androsmex.asn1.BSIObjectIdentifiers.id_PACE_DH_GM_AES_CBC_CMAC_192;
import static com.npa.androsmex.asn1.BSIObjectIdentifiers.id_PACE_DH_GM_AES_CBC_CMAC_256;
import static com.npa.androsmex.asn1.BSIObjectIdentifiers.id_PACE_DH_IM;
import static com.npa.androsmex.asn1.BSIObjectIdentifiers.id_PACE_DH_IM_3DES_CBC_CBC;
import static com.npa.androsmex.asn1.BSIObjectIdentifiers.id_PACE_DH_IM_AES_CBC_CMAC_128;
import static com.npa.androsmex.asn1.BSIObjectIdentifiers.id_PACE_DH_IM_AES_CBC_CMAC_192;
import static com.npa.androsmex.asn1.BSIObjectIdentifiers.id_PACE_DH_IM_AES_CBC_CMAC_256;
import static com.npa.androsmex.asn1.BSIObjectIdentifiers.id_PACE_ECDH_GM;
import static com.npa.androsmex.asn1.BSIObjectIdentifiers.id_PACE_ECDH_GM_3DES_CBC_CBC;
import static com.npa.androsmex.asn1.BSIObjectIdentifiers.id_PACE_ECDH_GM_AES_CBC_CMAC_128;
import static com.npa.androsmex.asn1.BSIObjectIdentifiers.id_PACE_ECDH_GM_AES_CBC_CMAC_192;
import static com.npa.androsmex.asn1.BSIObjectIdentifiers.id_PACE_ECDH_GM_AES_CBC_CMAC_256;
import static com.npa.androsmex.asn1.BSIObjectIdentifiers.id_PACE_ECDH_IM;
import static com.npa.androsmex.asn1.BSIObjectIdentifiers.id_PACE_ECDH_IM_3DES_CBC_CBC;
import static com.npa.androsmex.asn1.BSIObjectIdentifiers.id_PACE_ECDH_IM_AES_CBC_CMAC_128;
import static com.npa.androsmex.asn1.BSIObjectIdentifiers.id_PACE_ECDH_IM_AES_CBC_CMAC_192;
import static com.npa.androsmex.asn1.BSIObjectIdentifiers.id_PACE_ECDH_IM_AES_CBC_CMAC_256;
import static com.npa.androsmex.pace.DHStandardizedDomainParameters.modp1024_160;
import static com.npa.androsmex.pace.DHStandardizedDomainParameters.modp2048_224;
import static com.npa.androsmex.pace.DHStandardizedDomainParameters.modp2048_256;

import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Logger;

import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.params.DHParameters;
import org.spongycastle.math.ec.ECCurve.Fp;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.Arrays;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import com.npa.androsmex.asn1.AmDHPublicKey;
import com.npa.androsmex.asn1.AmECPublicKey;
import com.npa.androsmex.asn1.BSIObjectIdentifiers;
import com.npa.androsmex.asn1.DomainParameter;
import com.npa.androsmex.asn1.DynamicAuthenticationData;
import com.npa.androsmex.asn1.PaceDomainParameterInfo;
import com.npa.androsmex.asn1.PaceInfo;
import com.npa.androsmex.asn1.SecurityInfos;
import com.npa.androsmex.crypto.AmAESCrypto;
import com.npa.androsmex.crypto.AmCryptoProvider;
import com.npa.androsmex.crypto.AmDESCrypto;
import com.npa.androsmex.iso7816.SecureMessaging;
import com.npa.androsmex.iso7816.SecureMessagingException;
import com.npa.androsmex.tools.Converter;
import com.npa.emulator.NPAEmulator;
import com.npa.tools.Tools;
//import de.tsenger.androsmex.IsoDepCardHandler;

public class PaceOperator {

//	private final IsoDepCardHandler card;
	private Logger logger;
	private int passwordRef = 0;
	private int terminalType = 0;
	private byte[] passwordBytes;
	private byte[] derivatedPassword;
	private String protocolOIDString;
	private DHParameters dhParameters = null;
	private X9ECParameters ecdhParameters = null;
	private Pace pace = null;
	private int keyLength = 0;
	private AmCryptoProvider crypto = null;
	private SecureMessaging sm;

	private DomainParameter dp = null;
	
	long starttime = 0;
	long endtime = 0;
	
	// by Ole
	byte[] nonce_s;
	byte[] nonce_z;
	byte[] X1;
	byte[] Y1;
	byte[] X2;
	byte[] Y2;
	byte[] tpcd;
	byte[] tpicc;
	private NPAEmulator npa;
	

//	public PaceOperator(IsoDepCardHandler card, Context context) {
//		this.card = card;
//		this.context = context;
//	}
	
	public PaceOperator(NPAEmulator npa) {
		this.npa = npa;
	}
	
	// by ole
	public void setAuthTemplate(PaceInfo pi) {

		dp = new DomainParameter(pi.getParameterId());

		protocolOIDString = pi.getProtocolOID();


		getStandardizedDomainParameters(pi.getParameterId());

		if (protocolOIDString.startsWith(id_PACE_DH_GM.toString()) || protocolOIDString.startsWith(id_PACE_DH_IM.toString()))
			pace = new PaceDH(dhParameters);
		else if (protocolOIDString.startsWith(id_PACE_ECDH_GM.toString()) || protocolOIDString.startsWith(id_PACE_ECDH_IM.toString()))
			pace = new PaceECDH(ecdhParameters);

		getCryptoInformation(pi);
	}

	public void setAuthTemplate(PaceInfo pi, String password, Logger logger, SharedPreferences prefs) {

		dp = new DomainParameter(pi.getParameterId());
		this.logger = logger;
		passwordRef = Integer.parseInt(prefs.getString("pref_list_password", "0"));
		terminalType = Integer.parseInt(prefs.getString("pref_list_terminal", "0"));

		protocolOIDString = pi.getProtocolOID();

		if (passwordRef == 1) passwordBytes = calcSHA1(password.getBytes());
		else passwordBytes = password.getBytes();

		getStandardizedDomainParameters(pi.getParameterId());

		if (protocolOIDString.startsWith(id_PACE_DH_GM.toString()) || protocolOIDString.startsWith(id_PACE_DH_IM.toString()))
			pace = new PaceDH(dhParameters);
		else if (protocolOIDString.startsWith(id_PACE_ECDH_GM.toString()) || protocolOIDString.startsWith(id_PACE_ECDH_IM.toString()))
			pace = new PaceECDH(ecdhParameters);

		getCryptoInformation(pi);
	}

	public void setAuthTemplate(PaceInfo pi, PaceDomainParameterInfo pdpi,
			String password, Logger logger, SharedPreferences prefs)
			throws Exception {

		this.logger = logger;
		protocolOIDString = pi.getProtocolOID();
		passwordRef = Integer.parseInt(prefs.getString("pref_list_password", "0"));
		terminalType = Integer.parseInt(prefs.getString("pref_list_terminal", "0"));

		if (pi.getParameterId() >= 0 && pi.getParameterId() <= 31)
			throw new Exception("ParameterID number 0 to 31 is used for standardized domain parameters!");
		if (pi.getParameterId() != pdpi.getParameterId())
			throw new Exception("PaceInfo doesn't match the PaceDomainParameterInfo");

		if (passwordRef == 1)
			passwordBytes = calcSHA1(password.getBytes());
		else
			passwordBytes = password.getBytes();

		getProprietaryDomainParameters(pdpi);

		if (protocolOIDString.startsWith(id_PACE_DH_GM.toString())
				|| protocolOIDString.startsWith(id_PACE_DH_IM.toString()))
			pace = new PaceDH(dhParameters);
		else if (protocolOIDString.startsWith(id_PACE_ECDH_GM.toString())
				|| protocolOIDString.startsWith(id_PACE_ECDH_IM.toString()))
			pace = new PaceECDH(ecdhParameters);

		getCryptoInformation(pi);
	}
	
	//////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////
	
	/**
	 * by Ole 
	 * Initialisiert den PaceOperator
	 * @param das Passwort fuer PACE
	 */
	public void initialize(String password) {
		keyLength = 128;
		crypto = new AmAESCrypto();
		byte[] sendSequenceCounter = new byte[16];
		passwordBytes = password.getBytes();
		derivatedPassword = getKey(keyLength, passwordBytes, 3);
		Log.i("PACE", "derivated Passwort: \t" + HexBytesToString(derivatedPassword));
		
		crypto.init(derivatedPassword, sendSequenceCounter);
	}
	
	/**
	 * by Ole 
	 * waehlt den entsprechenden PACE-Schritt aus.
	 * @param data der CommandAPDU
	 * @return data der entsprechenden ResponseAPDU
	 */
	public byte[] performPace(byte[] cmd_data) {
		// command get nonce
		if(cmd_data[0] == (byte)0x7C && cmd_data[1] == (byte)0x00) {
			Log.i("PACE", "perform Step 1");
			return step1();
		}
		
		DynamicAuthenticationData dad = new DynamicAuthenticationData(cmd_data);
		if(dad.getDataObject(1) != null) {
			Log.i("PACE", "perform Step 2");
			return step2(dad.getDataObject(1));
		}
		else if(dad.getDataObject(3) != null) {
			Log.i("PACE", "perform Step 3");
			return step3(dad.getDataObject(3));
		}
		else if(dad.getDataObject(5) != null) {
			Log.i("PACE", "perform Step 4");
			return step4(dad.getDataObject(5));
		}
		
		// return Command not allowed (general)
		return new byte[] {(byte)0x69, (byte)0x00};
	}
	
	/**
	 * by Ole 
	 * nonce_s und nonce_z werden erzeugt.
	 * @return ResponseAPDU, welche nonce_z enthaelt
	 */
	public byte[] step1() {	
//		new Random().nextBytes(nonce_s);
		nonce_s = hexStringToByteArray("7D 98 C0 0F C6 C9 E9 54 3B BF 94 A8 70 73 A1 23");
		nonce_z = encryptNonce(nonce_s);
		
		Log.i("PACE", "nonce_s: \t" + HexBytesToString(nonce_s));
		Log.i("PACE", "nonce_z: \t" + HexBytesToString(nonce_z));
		
		// Response APDU erstellen
		DynamicAuthenticationData dad_encrypted_nonce = new DynamicAuthenticationData();
		dad_encrypted_nonce.addDataObject(0, nonce_z);

		return dad_encrypted_nonce.getDEREncoded();
	}

	/**
	 * by Ole 
	 * Y1 wird erzeugt.
	 * @param CommandAPDU, welche X1 enthaelt
	 * @return ResponseAPDU, welche Y1 enthaelt
	 */
	public byte[] step2(byte[] dad_data) {

		X1 = dad_data;		
		Log.i("PACE", "X1: \t" + HexBytesToString(X1));			
		
		Y1 = pace.getY1(nonce_s);	
		Log.i("PACE", "Y1: \t" + HexBytesToString(Y1));		
		
		
		DynamicAuthenticationData dad_Y1 = new DynamicAuthenticationData();
		dad_Y1.addDataObject(2, Y1);

		return dad_Y1.getDEREncoded();
	}
	

	/**
	 * by Ole 
	 * Y2 wird berechnet.
	 * @param CommandAPDU, welche X2 enthaelt.
	 * @return ResponseAPDU, welche Y2 enthaelt.
	 */
	public byte[] step3(byte[] dad_data) {
		X2 = dad_data;		
		Log.i("PACE", "X2: \t" + HexBytesToString(X2));	
		
		Y2 = pace.getY2(X1);	
		Log.i("PACE", "Y2: \t" + HexBytesToString(Y2));	
		
		DynamicAuthenticationData dad_Y2 = new DynamicAuthenticationData();
		dad_Y2.addDataObject(4, Y2);
		
		return dad_Y2.getDEREncoded();
	}
	
	/**
	 * by Ole 
	 * SecureMessaging wird eingerichtet.
	 * @param CommandAPDU, welche tpcd
	 * @return ResponseAPDU, welche tpicc und car enthaelt
	 */
	public byte[] step4(byte[] dad_data) {

		tpcd = dad_data;
		
		Log.i("PACE", "tpcd: \t" + HexBytesToString(tpcd));
		
		byte[] S = pace.getSharedSecret_K(X2); 
		Log.i("PACE", "Shared Secret K: \t" + HexBytesToString(S));
		
		byte[] kenc = getKenc(S);
		Log.i("PACE", "kenc: \t" + HexBytesToString(kenc));
		
		byte[] kmac = getKmac(S);
		Log.i("PACE", "kmac: \t" + HexBytesToString(kmac));
		
		
		tpicc = calcAuthToken(kmac, X2);
		Log.i("PACE", "tpicc: \t" + HexBytesToString(tpicc));
		
		// Authentication Token T_PICC berechnen
		byte[] tpcd_strich = calcAuthToken(kmac, Y2);
		Log.i("PACE", "tpcd_strich: \t" + HexBytesToString(tpcd_strich));

		
		// Prüfe ob tpicc = t'picc=MAC(kmac,X2)
		if (!Arrays.areEqual(tpcd, tpcd_strich)) {
			Log.e("PACE", "Mutual Authentication failed! Tokens are different");
			//throw new PaceException("Mutual Authentication failed! Tokens are different");
		}
		else {
			sm = new SecureMessaging(crypto, kenc, kmac, new byte[crypto.getBlockSize()]);
			npa.setSMObject(sm);
		}
		
		DynamicAuthenticationData dad_tpicc_car = new DynamicAuthenticationData();
		dad_tpicc_car.addDataObject(6, tpicc);
		
//		byte[] car = Tools.stb("44 45 41 54 43 56 43 41 30 30 30 30 31");
		byte[] car = Tools.stb("44 45 43 56 43 41 65 49 44 30 30 31 30 33");
		dad_tpicc_car.addDataObject(7, car);
		
		System.out.println("tpicc_car_data" + Tools.bts(dad_tpicc_car.getDEREncoded()));
		return dad_tpicc_car.getDEREncoded();
	}
	
	//////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////

	
	public SecurityInfos getSecurityInfosFromCardAccess(String ef_cardaccess_string) {	
		byte[] ef_cardaccess = hexStringToByteArray(ef_cardaccess_string);
		SecurityInfos si = null;
		try {
			si = new SecurityInfos();
			si.decode(ef_cardaccess);
		} catch (IOException e) {}

		return si;
	}
	
	
	
//	public byte[] n_performStep2(byte[] nonce_s) {
//		byte[] X1 = pace.getX1(nonce_s);
//		return X1;
//	}	
//	public byte[] n_performStep3(byte[] Y1) {
//		byte[] X2 = pace.getX2(Y1);
//		return X2;
//	}		
//	public void n_performStep4(byte[] Y2, byte[] X2) throws SecureMessagingException, PaceException, IOException {
//		byte[] S = pace.getSharedSecret_K(Y2); 
//		byte[] kenc = getKenc(S);
//		byte[] kmac = getKmac(S);
//
//		// Authentication Token T_PCD berechnen
//		byte[] tpcd = calcAuthToken(kmac, Y2);
//
//		// Authentication Token zur Karte schicken
//		logger.log(Level.FINE, "4. General Authentication (mutual authentication) command");
//		byte[] tpicc = performMutualAuthentication(tpcd).getDataObject(6);
//
//		// Authentication Token T_PICC berechnen
//		byte[] tpicc_strich = calcAuthToken(kmac, X2);
//
//		// Prüfe ob tpicc = t'picc=MAC(kmac,X2)
//		if (!Arrays.areEqual(tpicc, tpicc_strich)) {
//			logger.log(Level.FINE, "Mutual Authentication failed! Tokens are different");
//			throw new PaceException("Mutual Authentication failed! Tokens are different");
//		}
//
//		sm = new SecureMessaging(crypto, kenc, kmac, new byte[crypto.getBlockSize()]);
//
//	}
	
	private String HexBytesToString(byte[] apdu) {
        StringBuilder sb = new StringBuilder();
        for(byte b : apdu){
            sb.append(String.format("%02x", b&0xff));
        }
        return sb.toString();
	}
	
	private byte[] hexStringToByteArray(String s) {
		s = s.replaceAll(" ", "");
        int len = s.length();
        byte[] data = new byte[len/2];

        for(int i = 0; i < len; i+=2){
            data[i/2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }

        return data;
    }
	
	//////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////

//	public void performPACE() throws IOException, SecureMessagingException, PaceException {
//
//		// send MSE:SetAT
//		logger.log(Level.FINE, "Send MSE:Set AT command");
//		int resp = sendMSESetAT(terminalType).getSW();
//		if (resp != 0x9000)
//			logger.log(Level.FINE, "MSE:Set AT failed. SW: " + Integer.toHexString(resp));
//
//		// send first GA and get nonce
//		logger.log(Level.FINE, "1. General Authentication (get nonce) command");
//		byte[] nonce_z = getNonce().getDataObject(0);
//		logger.log(Level.FINE, "encrypted nonce z:\n" + HexString.bufferToHex(nonce_z));
//		byte[] nonce_s = decryptNonce(nonce_z);
//		logger.log(Level.FINE, "decrypted nonce s:\n" + HexString.bufferToHex(nonce_s));
//		byte[] X1 = pace.getX1(nonce_s);
//
//		// X1 zur Karte schicken und Y1 empfangen
//		logger.log(Level.FINE, "2. General Authentication (map nonce) command");
//		byte[] Y1 = mapNonce(X1).getDataObject(2);;
//
//		byte[] X2 = pace.getX2(Y1);
//		// X2 zur Karte schicken und Y2 empfangen.
//		logger.log(Level.FINE, "3. General Authentication (key agreement) command");
//		byte[] Y2 = performKeyAgreement(X2).getDataObject(4);
//
//		byte[] S = pace.getSharedSecret_K(Y2); 
//		byte[] kenc = getKenc(S);
//		byte[] kmac = getKmac(S);
//		logger.log(Level.FINE, "Shared Secret K: " + HexString.bufferToHex(S) + "\nkenc: " + HexString.bufferToHex(kenc) + "\nkmac: "
//				+ HexString.bufferToHex(kmac));
//
//		// Authentication Token T_PCD berechnen
//		byte[] tpcd = calcAuthToken(kmac, Y2);
//
//		// Authentication Token zur Karte schicken
//		logger.log(Level.FINE, "4. General Authentication (mutual authentication) command");
//		byte[] tpicc = performMutualAuthentication(tpcd).getDataObject(6);
//
//		// Authentication Token T_PICC berechnen
//		byte[] tpicc_strich = calcAuthToken(kmac, X2);
//
//		// Prüfe ob tpicc = t'picc=MAC(kmac,X2)
//		if (!Arrays.areEqual(tpicc, tpicc_strich)) {
//			logger.log(Level.FINE, "Mutual Authentication failed! Tokens are different");
//			throw new PaceException("Mutual Authentication failed! Tokens are different");
//		}
//
//		sm = new SecureMessaging(crypto, kenc, kmac, new byte[crypto.getBlockSize()]);
//
//		card.setSecureMessaging(sm);
//
//	}

	/**
	 * Der Authentication Token berechnet sich aus dem MAC (mit Schlüssel kmac)
	 * über einen AmPublicKey welcher den Object Identifier des verwendeten
	 * Protokolls und den von der empfangenen ephemeralen Public Key (Y2)
	 * enthält. Siehe dazu TR-03110 V2.05 Kapitel A.2.4 und D.3.4 Hinweis: In
	 * älteren Versionen des PACE-Protokolls wurden weitere Parameter zur
	 * Berechnung des Authentication Token herangezogen.
	 * 
	 * @param data
	 *            Byte-Array welches ein DO84 (Ephemeral Public Key) enthält
	 * @param kmac
	 *            Schlüssel K_mac für die Berechnung des MAC
	 * @return Authentication Token
	 */
	private byte[] calcAuthToken(byte[] kmac, byte[] data) {
		byte[] tpcd = null;
		if (pace instanceof PaceECDH) {
			Fp curve = (Fp) dp.getECParameter().getCurve();
			ECPoint pointY = Converter.byteArrayToECPoint(data, curve);
			AmECPublicKey pkpcd = new AmECPublicKey(protocolOIDString, pointY);
			tpcd = crypto.getMAC(kmac, pkpcd.getEncoded());
		} else if (pace instanceof PaceDH) {
			BigInteger y = new BigInteger(data);
			AmDHPublicKey pkpcd = new AmDHPublicKey(protocolOIDString, y);
			tpcd = crypto.getMAC(kmac, pkpcd.getEncoded());
		}
		return tpcd;
	}

	/**
	 * Send a plain General Authentication Command to get a encrypted nonce from
	 * the card.
	 * 
	 * @return
	 * @throws IOException
	 * @throws PaceException
	 * @throws SecureMessagingException
	 * @throws Exception
	 */
//	private DynamicAuthenticationData getNonce() throws SecureMessagingException, PaceException, IOException {
//		byte[] data = new byte[] { 0x7C, 0x00 };
//		return sendGeneralAuthenticate(true, data);
//	}

//	private DynamicAuthenticationData sendGeneralAuthenticate(boolean chaining, byte[] data) throws SecureMessagingException, PaceException, IOException {
//
//		CommandAPDU capdu = new CommandAPDU(chaining ? 0x10 : 0x00, 0x86, 0x00, 0x00, data, 0xff);
//
//		ResponseAPDU resp = card.transceive(capdu);
//
//		if (resp.getSW() != 0x9000)
//			throw new PaceException("General Authentication returns: "	+ HexString.bufferToHex(resp.getBytes()));
//
//		DynamicAuthenticationData dad = new DynamicAuthenticationData(resp.getData());
//		return dad;
//	}

//	private DynamicAuthenticationData mapNonce(byte[] mappingData)
//			throws SecureMessagingException, PaceException, IOException {
//
//		DynamicAuthenticationData dad81 = new DynamicAuthenticationData();
//		dad81.addDataObject(1, mappingData);
//
//		return sendGeneralAuthenticate(true, dad81.getDEREncoded());
//	}

//	private DynamicAuthenticationData performMutualAuthentication(
//			byte[] authToken) throws SecureMessagingException, PaceException,
//			IOException {
//
//		DynamicAuthenticationData dad85 = new DynamicAuthenticationData();
//		dad85.addDataObject(5, authToken);
//
//		return sendGeneralAuthenticate(false, dad85.getDEREncoded());
//	}

//	private DynamicAuthenticationData performKeyAgreement(byte[] ephemeralPK)
//			throws PaceException, SecureMessagingException, IOException {
//
//		DynamicAuthenticationData dad83 = new DynamicAuthenticationData();
//		dad83.addDataObject(3, ephemeralPK);
//
//		return sendGeneralAuthenticate(true, dad83.getDEREncoded());
//	}
	
	// Added by erik
	private byte[] encryptNonce(byte[] s) {
		System.out.println("perform encryptNonce.");
		return ((AmAESCrypto) crypto).encryptBlock(derivatedPassword, s);
	}

	private byte[] decryptNonce(byte[] z) {
		byte[] derivatedPassword = null;
		derivatedPassword = getKey(keyLength, passwordBytes, 3);
		return crypto.decryptBlock(derivatedPassword, z);
	}

	private byte[] getKenc(byte[] sharedSecret_S) {
		return getKey(keyLength, sharedSecret_S, 1);
	}

	private byte[] getKmac(byte[] sharedSecret_S) {
		return getKey(keyLength, sharedSecret_S, 2);
	}

//	private ResponseAPDU sendMSESetAT(int terminalType) throws IOException, SecureMessagingException {
//		MSESetAT mse = new MSESetAT();
//		mse.setAT(MSESetAT.setAT_PACE);
//		mse.setProtocol(protocolOIDString);
//		mse.setKeyReference(passwordRef);
//		switch (terminalType) {
//		case 0:
//			break;
//		case 1:
//			mse.setISChat();
//			break;
//		case 2:
//			mse.setATChat();
//			break;
//		case 3:
//			mse.setSTChat();
//			break;
//		default:
//			throw new IllegalArgumentException("Unknown Terminal Reference: "
//					+ terminalType);
//		}
//		return card.transceive(mse.getCommandAPDU());
//	}

	private void getStandardizedDomainParameters(int parameterId) {

		switch (parameterId) {
		case 0:
			dhParameters = modp1024_160();
			break;
		case 1:
			dhParameters = modp2048_224();
			break;
		case 3:
			dhParameters = modp2048_256();
			break;
		case 8:
			ecdhParameters = SECNamedCurves.getByName("secp192r1");
			break;
		case 9:
			ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp192r1");
			break;
		case 10:
			ecdhParameters = SECNamedCurves.getByName("secp224r1");
			break;
		case 11:
			ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp224r1");
			break;
		case 12:
			ecdhParameters = SECNamedCurves.getByName("secp256r1");
			break;
		case 13:
			ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp256r1");
			break;
		case 14:
			ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp320r1");
			break;
		case 15:
			ecdhParameters = SECNamedCurves.getByName("secp384r1");
			break;
		case 16:
			ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp384r1");
			break;
		case 17:
			ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp512r1");
			break;
		case 18:
			ecdhParameters = SECNamedCurves.getByName("secp521r1");
			break;
		}
	}

	private byte[] getKey(int keyLength, byte[] K, int c)  {

		byte[] key = null;

		KeyDerivationFunction kdf = new KeyDerivationFunction(K, c);

		switch (keyLength) {
		case 112:
			key = kdf.getDESedeKey();
			break;
		case 128:
			key = kdf.getAES128Key();
			break;
		case 192:
			key = kdf.getAES192Key();
			break;
		case 256:
			key = kdf.getAES256Key();
			break;
		}
		return key;
	}

	// TODO Funktioniert momentan nur mit EC
	private void getProprietaryDomainParameters(PaceDomainParameterInfo pdpi)	throws PaceException {
		if (pdpi.getDomainParameter().getAlgorithm().toString()
				.contains(BSIObjectIdentifiers.id_ecc.toString())) {
			ASN1Sequence seq = (ASN1Sequence) pdpi.getDomainParameter()
					.getParameters().getDERObject().toASN1Object();
			ecdhParameters = new X9ECParameters(seq);
		} else
			throw new PaceException(
					"Can't decode properietary domain parameters in PaceDomainParameterInfo!");
	}

	/**
	 * Ermittelt anhand der ProtokollOID den Algorithmus und die Schlüssellänge
	 * für PACE
	 */
	private void getCryptoInformation(PaceInfo pi) {
		String protocolOIDString = pi.getProtocolOID();
		if (protocolOIDString.equals(id_PACE_DH_GM_3DES_CBC_CBC.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_3DES_CBC_CBC
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_3DES_CBC_CBC
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_3DES_CBC_CBC
						.toString())) {
			keyLength = 112;
			crypto = new AmDESCrypto();
		} else if (protocolOIDString.equals(id_PACE_DH_GM_AES_CBC_CMAC_128
				.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_AES_CBC_CMAC_128
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_AES_CBC_CMAC_128
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_AES_CBC_CMAC_128
						.toString())) {
			keyLength = 128;
			crypto = new AmAESCrypto();
		} else if (protocolOIDString.equals(id_PACE_DH_GM_AES_CBC_CMAC_192
				.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_AES_CBC_CMAC_192
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_AES_CBC_CMAC_192
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_AES_CBC_CMAC_192
						.toString())) {
			keyLength = 192;
			crypto = new AmAESCrypto();
		} else if (protocolOIDString.equals(id_PACE_DH_GM_AES_CBC_CMAC_256
				.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_AES_CBC_CMAC_256
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_AES_CBC_CMAC_256
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_AES_CBC_CMAC_256
						.toString())) {
			keyLength = 256;
			crypto = new AmAESCrypto();
		}
	}

	/**
	 * Berechnet den SHA1-Wert des übergebenen Bytes-Array
	 * 
	 * @param input
	 *            Byte-Array des SHA1-Wert berechnet werden soll
	 * @return SHA1-Wert vom übergebenen Byte-Array
	 */
	private byte[] calcSHA1(byte[] input) {
		byte[] md = new byte[20];
		SHA1Digest sha1 = new SHA1Digest();
		sha1.update(input, 0, input.length);
		sha1.doFinal(md, 0);
		return md;
	}

	public SecureMessaging getSMObject() {
		return sm;
	}

//	@Override
//	protected String doInBackground(Void... params) {
//				
//		try {
//			starttime = System.currentTimeMillis();
//			performPACE();
//			
//		} catch (IOException e) {
//			logger.log(Level.FINE, e.getMessage());
//			return "PACE failed!";
//		} catch (SecureMessagingException e) {
//			logger.log(Level.FINE, e.getMessage());
//			return "PACE failed!";
//		} catch (PaceException e) {
//			logger.log(Level.FINE, e.getMessage());
//			return "PACE failed!";
//		} finally {
//			endtime = System.currentTimeMillis();
//		}
//		
//		return "PACE established!";
//	}

//	@Override
//	protected void onProgressUpdate(String... strings) {
//		if (strings != null) {
//			logger.log(Level.INFO, strings[0]);
//		}
//	}

//	@Override
//	protected void onPostExecute(String result) {
//				
//		Intent intent = new Intent("pace_finished");
//		intent.putExtra("message", result+"\nTime used: " + (endtime - starttime) + " ms");
//		LocalBroadcastManager.getInstance(context).sendBroadcast(intent);
//	}
//
}
