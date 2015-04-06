package com.npa.gui;

import android.app.ActionBar;
import android.app.ActionBar.Tab;
import android.app.Fragment;
import android.app.FragmentTransaction;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.os.Bundle;
import android.support.v4.app.FragmentActivity;
import android.support.v4.view.ViewPager;
import android.text.Html;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import com.npa.nfc.EmulatorNfcIO;





public class MainActivity extends FragmentActivity implements ActionBar.TabListener {

    private static final String TAG = MainActivity.class.getSimpleName();
    private NfcAdapter mAdapter;
    private PendingIntent mPendingIntent;
    private IntentFilter[] mFilters;
    private String[][] mTechLists;
    
	private Thread NfcThr = null;
	private EmulatorNfcIO enfc;
    
	private ViewPager viewPager;
    private TabsPagerAdapter tpAdapter;
    private ActionBar actionBar;
    // Tab titles
    private String[] tabs = { "Access Rights", "Certificate", "Log"};
    
	public static MainActivity ma;
	
    
    private BroadcastReceiver uiUpdated = new BroadcastReceiver() {
    	
        @Override
        public void onReceive(Context context, Intent intent) {
        	if(intent.getExtras().getString("CHAT") != null) {
            	TextView access_rights = (TextView) findViewById(R.id.access_rights_textfield);
        		access_rights.setText(Html.fromHtml(intent.getExtras().getString("CHAT")));
        	}
        	if(intent.getExtras().getString("LOG") != null) {
            	TextView log = (TextView) findViewById(R.id.log_textfield);
        		log.append(Html.fromHtml(intent.getExtras().getString("LOG")));
        	}
        	if(intent.getExtras().getString("CERT") != null) {
            	TextView certificate_information = (TextView) findViewById(R.id.certificate_information_textfield);
            	certificate_information.append(Html.fromHtml(intent.getExtras().getString("CERT")));
        	}
        }
    };
    
    
	@Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        ma=this;
        
        setContentView(R.layout.activity_main);
 
        registerReceiver(uiUpdated, new IntentFilter("CHAT_UPDATED"));

        // Initilization
        viewPager = (ViewPager) findViewById(R.id.pager);
        viewPager = (ViewPager)findViewById(R.id.pager);
        viewPager.setOffscreenPageLimit(3);
        
        actionBar = getActionBar();
        tpAdapter = new TabsPagerAdapter(getSupportFragmentManager());
 
        viewPager.setAdapter(tpAdapter);
        /**
         * on swiping the viewpager make respective tab selected
         * */
        viewPager.setOnPageChangeListener(new ViewPager.OnPageChangeListener() {
         
            @Override
            public void onPageSelected(int position) {
                // on changing the page
                // make respected tab selected
                actionBar.setSelectedNavigationItem(position);
            }
         
            @Override
            public void onPageScrolled(int arg0, float arg1, int arg2) {
            }
         
            @Override
            public void onPageScrollStateChanged(int arg0) {
            }
            
            
        });
        
        actionBar.setHomeButtonEnabled(false);
        actionBar.setNavigationMode(ActionBar.NAVIGATION_MODE_TABS);       
 
        // Adding Tabs
        for (String tab_name : tabs) {
            actionBar.addTab(actionBar.newTab().setText(tab_name)
                    .setTabListener(this));
        }

        
        mAdapter = NfcAdapter.getDefaultAdapter(this);
        
		mPendingIntent = PendingIntent.getActivity(this, 0, new Intent(this,
	                getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
	    mFilters = new IntentFilter[] { new IntentFilter(
	                NfcAdapter.ACTION_TECH_DISCOVERED) };
	    mTechLists = new String[][] { { "android.nfc.tech.IsoPcdA" } };

	}

	
	public void onResume() {
	    super.onResume();
	    Log.i(TAG, "function start");
	    if (mAdapter != null) {
	      mAdapter.enableForegroundDispatch(this, mPendingIntent, mFilters, mTechLists);
	      Log.i("foregrounddispatch","enabled");
	    }
	}
	
	public void onPause() {
	    super.onPause();
	    if (mAdapter != null) {
	      mAdapter.disableForegroundDispatch(this);
	    }
	}
	  
	@Override
	protected void onNewIntent(Intent intent) {
		  	
		enfc = new EmulatorNfcIO(this, intent);
		NfcThr = new Thread(enfc);
		NfcThr.start();
		Log.i("onNewIntent:NfcThr", "EmulatorNfcIO Thread is started.");

	}


	@Override
	public boolean onCreateOptionsMenu(Menu menu) {

		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();
		if (id == R.id.action_settings) {
			return true;
		}
		return super.onOptionsItemSelected(item);
	}

	/**
	 * A placeholder fragment containing a simple view.
	 */
	public static class PlaceholderFragment extends Fragment {

		public PlaceholderFragment() {
		}

		@Override
		public View onCreateView(LayoutInflater inflater, ViewGroup container,
				Bundle savedInstanceState) {
			View rootView = inflater.inflate(R.layout.fragment_main, container,
					false);
			return rootView;
		}
	}

	@Override
    public void onTabReselected(Tab tab, FragmentTransaction ft) {
    }
 
    @Override
    public void onTabSelected(Tab tab, FragmentTransaction ft) {
        // on tab selected
        // show respected fragment view
        viewPager.setCurrentItem(tab.getPosition());
    }
 
    @Override
    public void onTabUnselected(Tab tab, FragmentTransaction ft) {
    }
    
    


}
