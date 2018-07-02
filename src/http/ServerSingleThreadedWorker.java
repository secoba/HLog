package http;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import burp.Tab_SimpleHttpServer;

/**
 * A Server with a single "Worker thread" - serves one client after the next.
 */
class ServerSingleThreadedWorker extends Thread implements Runnable {

	private final int port;
	private final int timeout;
	ServerSocket socketServer;
	RequestHandlerFactory requestHandlerFactory;

	public ServerSingleThreadedWorker(int port, int timeout, RequestHandlerFactory requestHandlerFactory) {
		this.port = port;
		this.timeout = timeout;
		this.requestHandlerFactory = requestHandlerFactory;
	}

	/**
	 * Run the server. This is a blocking call - run() will not return, unless another thread sets runServer = false.
	 */
	@Override
	public void run() {
		try {
			while (!isInterrupted()) {
				Socket socket = socketServer.accept();

				socket.setSoTimeout(timeout);

				RequestHandler handler = requestHandlerFactory.newRequestHandler(socket);
				this.handle(handler);
			}
		} 	
		catch (IOException ex) {
			// This throw is probably not going anywhere anyway - there can be no catch for this
			throw new RuntimeException("Unexpected problem during Socket listening", ex);
		}
	}

	@Override
	public void start() {
		try {
			// Set runningServer=true here - that's the responsability of start()
			socketServer = new ServerSocket(port);
			super.start();

		} 
		catch (Exception ex) {
			// This throw is probably not going anywhere anyway - there can be no catch for this...
			Tab_SimpleHttpServer.msg(ex.getMessage());
			throw new RuntimeException("Unexpected problem during Socket binding", ex);
		}
	}

	public void terminate() {
		try {
			if (socketServer != null) {
				socketServer.close();
			}
			this.interrupt();
		} catch (IOException ex) { }
	}

	/**
	 * Serve the request from socket. Subclasses can override this method.
	 */
	protected void handle(RequestHandler handler) {
		handler.run();
	}
}
