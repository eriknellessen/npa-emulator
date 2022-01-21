package com.npa.gui;

import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

public class AccessRightsFragment extends Fragment {

	
   @Override
   public View onCreateView(LayoutInflater inflater, ViewGroup container,
           Bundle savedInstanceState) {

       View rootView = inflater.inflate(R.layout.fragment_access_rights, container, false);
       
       return rootView;
   }
   
   @Override
   public void onSaveInstanceState(Bundle outState) {
       super.onSaveInstanceState(outState);
   }
   
   @Override
   public void onActivityCreated(Bundle savedInstanceState) {
       super.onActivityCreated(savedInstanceState);
   }
}