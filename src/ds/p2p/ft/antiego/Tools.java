package ds.p2p.ft.antiego;

import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
/**
 * @author Ali Shoker
 *
 */

public class Tools {


	public static enum AccountObjectType {ACCOUNT_ENTRY, ACCOUNT_CERTIFICATE;}

	public Map<Long, Object> deepCopy(Map<Long, Object> map,AccountObjectType type){


		switch (type) {
		case ACCOUNT_ENTRY:
			break;
		case ACCOUNT_CERTIFICATE:
		default:
			break;
		}


		return map;

	}

	public static class Timing {
		public static final long ASK_WAITING_TIME=30000;//time in milliseconds
	}

	public static class AMSTimer{

		private Long startTime;
		private Long endTime;
		private TimeUnit timeUnit=TimeUnit.MILLISECONDS;//possible is ms and us or ns


		public void start(TimeUnit timeUnit){

			if (timeUnit!=null) this.timeUnit= timeUnit;

			switch(timeUnit){
			case MICROSECONDS:
				startTime = System.nanoTime()*1000;
			case NANOSECONDS:
				startTime = System.nanoTime();
			default:
				startTime = System.currentTimeMillis();
			}
		}

		public void start(){
			startTime = System.currentTimeMillis();
		}

		public Long stop(){

			switch(timeUnit){
			case MICROSECONDS:
				endTime = System.nanoTime()*1000;
			case NANOSECONDS:
				endTime = System.nanoTime();
			default:
				endTime = System.currentTimeMillis();
			}

			return endTime - startTime;
		}
	}
	
	public static class Trace {


	    private static final Level   LOGGING_LEVEL  = Level.INFO; 
	    
		static final Logger LOG = Logger.getLogger("Node"); 
		
		public static void setLogLevel(Level loggingLevel){
			LOG.setLevel(loggingLevel);
			
		}

	    public static void e(String tag, String msg)
	    {
	        if ( LOGGING_LEVEL==Level.SEVERE) LOG.severe(tag+msg);
	    }

	    public static void w(String tag, String msg)
	    {
	        if ( LOGGING_LEVEL==Level.WARNING) LOG.warning(tag+msg);
	    }

	    public static void i(String tag, String msg)
	    {
	        if ( LOGGING_LEVEL==Level.INFO) LOG.info(tag+msg);
	    }

	    public static void d(String tag, String msg)
	    {
	        if ( LOGGING_LEVEL==Level.INFO) LOG.info(tag+ msg);
	    }

	}
	
}
