package http;

import java.io.IOException;
import java.net.Socket;

/**
 * Handling Network Socket Requests. This is "general-purpose" so far and could handle different protcols (i.e. it is NOT tied to HTTP).
 */
abstract class RequestHandler implements Runnable {
	private final Socket socket;

	public RequestHandler(Socket socket) {
		this.socket = socket;
	}

	/**
	 * Handle a request given a Socket - read stuff from it - answer stuff back, etc!
	 */
	protected abstract void handle(Socket socket) throws IOException, SimpleWebServerException;

	public void run() {
		try {
			handle(socket);
		} catch (Exception ex) { } finally {
			try {
				// Should never be null, but let's be on the safe side anyway
				if (socket != null) {
					// Some options, faster & safer
					socket.setSoLinger(false, 0);
					socket.shutdownInput();
					socket.shutdownOutput();
					socket.close();
				}
			} catch (IOException e) {
				// Ignore... OK.
			}
		}
	}
}
