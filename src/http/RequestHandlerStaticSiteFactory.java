package http;

import java.io.File;
import java.net.Socket;

/**
 * Implementation of RequestHandlerFactory returning RequestHandlerStaticSite.
 */
class RequestHandlerStaticSiteFactory implements RequestHandlerFactory {

	File rootDirectory;

	public RequestHandlerStaticSiteFactory(File rootDirectory) {
		this.rootDirectory = rootDirectory;
	}

	public RequestHandler newRequestHandler(Socket socket) {
		return new RequestHandlerStaticSite(socket, rootDirectory);
	}
}
