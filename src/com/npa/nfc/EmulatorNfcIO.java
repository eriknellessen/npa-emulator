package com.npa.nfc;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

import android.content.Context;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.util.Log;

import com.npa.emulator.NPAEmulator;

public class EmulatorNfcIO implements Runnable{

    public BasicTagTechnologyWrapper mf;
    private Tag tag;
    private volatile boolean running = true;
    
	private NPAEmulator npa;


	
	public EmulatorNfcIO(Context ctx, Intent intent) {
		npa = new NPAEmulator(ctx, "123456");
		
		tag = (Tag) intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
		try {
			mf = new BasicTagTechnologyWrapper(tag, "android.nfc.tech.IsoPcdA");
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchMethodException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvocationTargetException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void terminate() {
    	running = false;
    }
	
	@Override
	public void run() {
		byte[] cmd = null;
			if(!mf.isConnected() || true) {
				try {
					mf.connect();
					cmd = mf.transceive(new byte[] {(byte) 0x90,0x00}); //initial Communication
				} 
				catch (IOException ioe) {
					ioe.printStackTrace();
				}
			}
			
			while(mf.isConnected() && running){
				try {
					byte[] response = processCommandApdu(cmd);	
					
//				    try {
//					Thread.sleep(200);
//				    } catch (InterruptedException e) {}
					
					cmd = mf.transceive(response);
					
					
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					Log.i("RederNfcIO:run()", "transceive failed.");
				}
			}
			Log.i("EmulatorNfcIO:run()", "Connection to NFC device closed");
		
	}
	
    public byte[] processCommandApdu(byte[] apdu) {
		
		// verarbeite cmd
		byte[] rapdu = npa.processCommandApdu(apdu);


	    
	    return rapdu;

    }
	


}
