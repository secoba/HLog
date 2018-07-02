package http;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;

import javax.activation.MimetypesFileTypeMap;

import burp.Tab_SimpleHttpServer;

/**
 * Handle HTTP requests from the local filesystem. Given a root directory, files corresponding to the URI are sent to the client.
 */
class RequestHandlerStaticSite extends RequestHandlerHTTP10 {

	File siteRoot;

	public RequestHandlerStaticSite(Socket socket, File htDocsRootPath) {
		super(socket);
		siteRoot = htDocsRootPath;
	}

	/**
	 * Handle GET request
	 */
	protected void handleGet(HTTPRequest request, HTTPResponse response) throws IOException {
		// The JDK URI class can do RFC 2396 encoding and decoding for us here
		URI uri;
		try {
			uri = new URI(request.getURI());
		} catch (URISyntaxException e) {
			// 400 is Bad Request, seems a suitable answer for this case
			response.setStatusCode(400);
			handleException(request, response, "URISyntaxException", e);
			return;
		}
		
		// Whether manual content-type
		if (!Tab_SimpleHttpServer.getDefaultRadioButton().isSelected()) {
			handleContent(Tab_SimpleHttpServer.getTextAreaResp().getText(), response);
		} else {			
			// If not, corresponding default
			File file = new File(siteRoot, uri.getPath());
			if (!file.exists()) {
				// 404 is 'Not Found', the correct answer for this case
				response.setStatusCode(404);
				handleError(request, response, "File Not Found for requested URI '" + uri + "' ");
				return;
			}
			if (!file.canRead()) {
				// 403 is 'Forbidden'
				response.setStatusCode(403);
				handleError(request, response, "Local file matched by requested URI is not readable");
				return;
			}
			
			if (file.isFile()) {
				handleFile(file, response);
			} else if (file.isDirectory()) {
				handleDir(file, response);
			} else {
				handleError(request, response, "Content not file, not directory. We don't know how to handle it.");
			}
		}
	}
	
	/**
	 * Handle manual response content
	 */
	private static void handleContent(String content, HTTPResponse response) throws IOException {
		try {
			OutputStream os = response.getOutputStream();
			os.write(content.getBytes());
			os.close();
		} catch (Exception e) {
			throw new IOException("Manual Content error: " + e.getMessage());
		}
	}

	/**
	 * Handle file request
	 */
	private static void handleFile(File file, HTTPResponse response) throws IOException {
		String filename = file.getName().toLowerCase();
		String contentType = getContentType(filename);
		response.setContentType(contentType);

		long length = file.length();
		response.setHeader(HTTPResponse.Header.ContentLength, Long.toString(length));

		FileInputStream in;
		try {
			in = new FileInputStream(file);

			OutputStream os = response.getOutputStream();

			int c;
			while ((c = in.read()) != -1) {
				os.write(c);
			}

			in.close();
			os.close();
		} catch (FileNotFoundException ex) {
			throw new IOException("File " + file + " not found.", ex);
		}
	}

	private static String getContentType(String filename) {
		if (filename.endsWith(".js")) {
			return "application/javascript";
		} else if (filename.endsWith(".css")) {
			return "text/css";
		} else {
			return new MimetypesFileTypeMap().getContentType(filename);
		}
	}

	private void handleDir(File dir, HTTPResponse response) throws IOException {
		File indexFile = new File(dir.getAbsolutePath() + File.separator + "index.html");
		if (indexFile.exists()) {
			redirect(indexFile, response);
		} else {
			StringBuilder builder = new StringBuilder(
					"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\"><html> \n"
					+ "<title>Directory listing for /</title>\n" 
					+ "<body>\n" 
					+ "<h2>Directory listing</h2>\n"
					+ "<hr>\n" 
					+ "<ul>");

			File[] files = dir.listFiles();
			for (File file : files) {
				String link = "<li><a href=\"" + getWebPath(file) + "\">" + file.getName() + "<a/></li>\n";
				builder.append(link);
			}
			builder.append("</ul>\n" + "<hr>\n" + "</body>\n" + "</html>");
			String content = builder.toString();
			response.setHeader(HTTPResponse.Header.ContentLength, Long.toString(content.length()));
			response.setContentType("text/html");
			OutputStream os = response.getOutputStream();
			os.write(content.getBytes("utf-8"));
			os.close();
		}
	}

	private String getWebPath(File file) throws IOException {
		return file.getCanonicalPath().replace(siteRoot.getCanonicalPath(), "");
	}

	private void redirect(File file, HTTPResponse response) throws IOException {
		response.setStatusCode(302);
		response.setHeader("Location", getWebPath(file));
	}

	@Override
	protected void handle(HTTPRequest request, HTTPResponse response) throws IOException {
		try {
			if (!HTTPRequest.Method.GET.toString().equals(request.getMethod())) {
				// 501 is "Not Implemented"
				response.setStatusCode(501);
				return;
			} else {
				handleGet(request, response);
			}

		} catch (Exception ex) {
			handleException(request, response, "Server Error (Unexpected '" + ex.getMessage() + "' while handling request)", ex);
		}
	}

	private void handleError(HTTPRequest request, HTTPResponse response, String message) throws IOException {
		this.handleException(request, response, message, null);
	}

	private void handleException(HTTPRequest request, HTTPResponse response, String message, Exception ex)
			throws IOException {
		try {
			if (response.getStatusCode() == 200) {
				response.setStatusCode(500);
			}
			PrintWriter pw;
			response.setContentType("text/html");
			pw = response.getPrintWriter();

			pw.println("<html><head><title>Server Error</title></head><body><h1>Server Error</h1><p>");
			pw.println(message);
			pw.println("</p><pre>");
			if (ex != null) {
				ex.printStackTrace(pw);
			}
			pw.println("</pre></body></html>");
		} catch (IllegalStateException e) {
			System.out.println("Can't send stack trace to client because "
					+ "OutputStream was already open for "
					+ "something else: " + e.toString());
			System.out.println("Stack trace of where the IllegalStateException occured:");
			e.printStackTrace();
			return;
		}
	}
}
