package http;

import java.net.Socket;

interface RequestHandlerFactory {
	public RequestHandler newRequestHandler(Socket socket);
}
