package com.npa.gui;



import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentPagerAdapter;

public class TabsPagerAdapter extends FragmentPagerAdapter {

   public TabsPagerAdapter(FragmentManager fm) {
       super(fm);
   }

   @Override
   public Fragment getItem(int index) {

       switch (index) {
       case 0:
           // Access Rights fragment activity
           return new AccessRightsFragment();
       case 1:
           // Certificate Information fragment activity
           return new CertificateInformationFragment();
       case 2:
           // Log fragment activity
           return new LogFragment();
       }
       return null;
   }

   @Override
   public int getCount() {
       // get item count - equal to number of tabs
       return 3;
   }

}
