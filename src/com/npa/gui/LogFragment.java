package com.npa.gui;

import com.npa.gui.R;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

public class LogFragment extends Fragment {

	int mCurCheckPosition = 0;

   @Override
   public View onCreateView(LayoutInflater inflater, ViewGroup container,
           Bundle savedInstanceState) {

       View rootView = inflater.inflate(R.layout.fragment_log, container, false);
        
       
       return rootView;
   }
   
   @Override
   public void onSaveInstanceState(Bundle outState) {
       super.onSaveInstanceState(outState);
       outState.putInt("curChoice", mCurCheckPosition);
   }
   
   @Override
   public void onActivityCreated(Bundle savedInstanceState) {
       super.onActivityCreated(savedInstanceState);
   if (savedInstanceState != null) {
           // Restore last state for checked position.
           mCurCheckPosition = savedInstanceState.getInt("curChoice", 0);
       }
   }
}