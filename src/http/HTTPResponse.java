package http;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.SocketException;
import java.util.HashMap;
import java.util.Map;

final class HTTPResponse {

	private String HTTPVersion;
	private int statusCode;
	private String statusReason;
	private Map<String, String> headers;
	private boolean bodyUseStarted;
	private Exception bodyUseStartedFakeExceptionForStackTrace;
	private OutputStream osInternal;
	private OutputStream osClient;
	private PrintWriter pw;

	HTTPResponse(Socket socket) throws IOException {
		headers = new HashMap<String, String>();
		osInternal = new BufferedOutputStream(socket.getOutputStream());
		pw = null;
		bodyUseStarted = false;

		setHTTPVersion(HTTPRequest.Version.HTTP10);
		statusCode = 200;
		statusReason = "OK";
	}

	/**
	 * Get a PrintWriter to write response into.
	 */
	public PrintWriter getPrintWriter() throws IOException {
		if (osClient != null) {
			throw new IllegalStateException("Invalid getPrintWriter(), because getOutputStream() has already been called");
		}
		if (pw == null) {
			sendHeaders();
			OutputStreamWriter osw = new OutputStreamWriter(osInternal);
			pw = new PrintWriter(osw);
		}
		return pw;
	}

	/**
	 * Get an OutputStream to write response into.
	 */
	public OutputStream getOutputStream() throws IOException {
		if (pw != null) {
			throw new IllegalStateException("Invalid getOutputStream(), because getPrintWriter() has already been called");
		}
		if (osClient == null) {
			sendHeaders();
			osClient = osInternal;
		}
		return osClient;
	}

	public void flush() throws IOException {
		sendHeaders();
		if (pw != null) {
			pw.flush();
		}
		osInternal.flush();
	}

	void close() throws IOException {
		try {
			flush();
			if (pw != null) {
				pw.close();
			}
			osInternal.close();
		} catch (SocketException ex) { }
	}

	/**
	 * Version of HTTP that the client making this request can understand
	 */
	public String getHTTPVersion() {
		return HTTPVersion;
	}

	public void setHTTPVersion(HTTPRequest.Version version) {
		checkHeadersSent("HTTPVersion");
		HTTPVersion = version.toString();
	}

	public int getStatusCode() {
		return statusCode;
	}

	public void setStatusCode(int statusCode) {
		checkHeadersSent("StatusCode");
		this.statusCode = statusCode;
		if (statusCode != 200) {
			this.statusReason = "NOTOK";
			// http://www.w3.org/Protocols/rfc2616/rfc2616-sec6.html#sec6.1.1 for meaning";
		}
	}

	public void setHeader(String name, String value) {
		checkHeadersSent("Header");
		headers.put(name, value);
	}

	public void setHeader(Header header, String value) {
		setHeader(header.toString(), value);
	}

	enum Header {
		Age("Age"), 
		ETag("ETag"), 
		Location("Location"), 
		ProxyAuthenticate("Proxy-Authenticate"), 
		RetryAfter("Retry-After"), 
		Server("Server"), 
		Vary("Vary"), 
		WWWAuthenticate("WWW-Authenticate"),
		Connection("Connection"), 
		ContentLength("Content-Length"),
		ContentType("Content-Type"), 
		Date("Date");
		
		private final String header;

		Header(String header) {
			this.header = header;
		}

		public String toString() {
			return header;
		}
	}

	public void setContentType(String contentType) {
		setHeader(Header.ContentType.toString(), contentType);
	}

	private void sendHeaders() throws IOException {
		if (bodyUseStarted) {
			return;
		}

		bodyUseStarted = true;
		try {
			throw new Exception();
		} catch (Exception ex) {
			bodyUseStartedFakeExceptionForStackTrace = ex;
		}

		PrintWriter pw = new PrintWriter(osInternal);
		// Status Line
		pw.print(HTTPVersion);
		pw.print(' ');
		pw.print(statusCode);
		pw.print(' ');
		pw.print(statusReason);
		pw.print("\r\n");
		// Headers
		for (String headerKey : headers.keySet()) {
			pw.print(headerKey);
			pw.print(": ");
			pw.print(headers.get(headerKey));
			pw.print("\r\n");
		}
		// Separator
		pw.print("\r\n");
		// This is important, else this never gets written/sent:
		pw.flush();
		// Do NOT pw.close(); here yet... it would close the underlying OutputStream & Socket already now, much too early!
	}

	private void checkHeadersSent(String what) {
		if (bodyUseStarted) {
			throw new IllegalStateException(
					"Invalid now; headers already written/sent (use set" 
					+ what
					+ " before calling getPrintWriter() or getOutputStream() )  "
					+ "[NOTE: Chained exception contains calling stack trace when getPrintWriter() or getOutputStream() was called]",
					bodyUseStartedFakeExceptionForStackTrace);
		}
	}
}
