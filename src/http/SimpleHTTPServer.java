package http;

import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;

import burp.Tab_SimpleHttpServer;

/**
 * HttpServer Main
 */
public class SimpleHTTPServer {

	public static final int DEFAULT_PORT = 9988;
	public static final File DEFAULT_FILE = new File(System.getProperty("user.dir"));
	public static final int DEFAULT_TIMEOUT = 2000;
	public static final int DEFAULT_MAX_THREAD = 10;
	
	private int port;
	private File rootDir;
	private int maxThreads = DEFAULT_MAX_THREAD;
	private int clientTimeoutInMillis = DEFAULT_TIMEOUT;
	private ServerMultiThreadedWorkers server;
	private boolean started = false;

	public SimpleHTTPServer() {
		this(DEFAULT_PORT, DEFAULT_FILE);
	}

	public SimpleHTTPServer(int port, File rootDir) {
		this.port = port;
		this.rootDir = rootDir;
	}
	
	public boolean start() {
		if (!started) {
			RequestHandlerFactory requestHandlerFactory = new RequestHandlerStaticSiteFactory(rootDir);
			server = new ServerMultiThreadedWorkers(port, clientTimeoutInMillis, maxThreads, requestHandlerFactory);
			server.start();
			started = true;
			Tab_SimpleHttpServer.msg("Serving HTTP on 0.0.0.0 port " + port);
			return true;
		} else {
			String msg = "Server already started (HTTP port=" + port + ", rootDir=" + rootDir.getAbsolutePath() + ")";
			Tab_SimpleHttpServer.msg(msg);
			throw new RuntimeException(msg);
		}
	}
	
	/**
	 * Is started?
	 */
	public boolean isStarted() {
		return started;
	}

	/**
	 * Is stopped?
	 */
	public boolean stop() {
		if (started) {
			server.terminate();
			try {
				Thread.sleep(500);
				started = false;
				return true;
			} catch (InterruptedException ex) {
				Logger.getLogger(SimpleHTTPServer.class.getName()).log(Level.SEVERE, null, ex);
			}
		} else {
			String msg = "Server not started (HTTP port=" + port + ", rootDir=" + rootDir.getAbsolutePath() + ")";
			Tab_SimpleHttpServer.msg(msg);
		}
		return started;
	}
	
	/**
	 * Set server port
	 */
	public void setPort(int port) {
		this.port = port;
	}
	
	/**
	 * Set server base dir
	 */
	public void setRootDir(File rootDir) {
		this.rootDir = rootDir;
	}

	/**
	 * Set maxThreads
	 */
	public void setMaxThreads(int maxThreads) {
		this.maxThreads = maxThreads;
	}

	/**
	 * Set clientTimeoutInMillis
	 */
	public void setClientTimeoutInMillis(int clientTimeoutInMillis) {
		this.clientTimeoutInMillis = clientTimeoutInMillis;
	}

	/**
	 * Test Main
	 */
	public static void main(String[] args) throws Exception {
		System.out.println(1);
		/**
		int port = DEFAULT_PORT;
		if (args.length > 0) {
			port = Integer.parseInt(args[0]);
		}
		SimpleHTTPServer server = new SimpleHTTPServer(port, DEFAULT_FILE);
		System.out.println(server.started);
		server.start();
		System.out.println(server);
		System.out.println(server.started);
		Thread.sleep(2000);
		server.stop();
		System.out.println(server.started);
		System.out.println(server);
		server.start();
		System.out.println(server.started);
		Thread.sleep(2000);
		server.stop();
		System.out.println(server.started);
		*/
	}
}
