package de.blinkt.openvpn.fragments;

import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DialogFragment;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.widget.EditText;

import de.blinkt.openvpn.R;

/**
 * Created by Malik on 27.07.16.
 */
public class EnterPinDialogFragment extends DialogFragment {

   public interface enterPinDialogListener {

       public void onDialogPositiveClick (String pin);
       public void onDialogNegativeClick ();
   }

    enterPinDialogListener mListener;

    @Override
    public void onAttach(Context context) {
        super.onAttach(context);
        try {
            mListener = (enterPinDialogListener) context;

        }catch (ClassCastException e){
            throw new ClassCastException(context.toString() + " must implement NoticeDialogListener");
        }
    }

    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {

        LayoutInflater inflater = getActivity().getLayoutInflater();
        final EditText pin = (EditText)getActivity().findViewById(R.id.pinField);

        AlertDialog.Builder builder = new AlertDialog.Builder(getActivity());
        builder.setView(inflater.inflate(R.layout.enter_pin_dialog, null))
                .setTitle("Enter PIN")
                .setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int id) {
                        mListener.onDialogPositiveClick(pin.getText().toString());
                    }
                })
                .setPositiveButton("Ok", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int id) {
                        mListener.onDialogNegativeClick();
                    }
                });
        return builder.create();
    }


}
