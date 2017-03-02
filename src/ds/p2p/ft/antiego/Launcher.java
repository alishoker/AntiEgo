package ds.p2p.ft.antiego;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ds.p2p.ft.antiego.Tools.Trace;
/**
 * @author Ali Shoker
 *
 */



public class Launcher {

	public static void main(String [ ] args){

		final Boolean LOG_ON_DEVICE=true;// enable logging on device screen

		final  String TAG = "main";

		List<Thread> threadsPool;
		Trace.d(TAG, "App start up");
		threadsPool= new ArrayList<Thread>();
		Collections.synchronizedList(threadsPool);
		Trace.d(TAG, "Creating a Node.");
		new Node(threadsPool);


	}
}


