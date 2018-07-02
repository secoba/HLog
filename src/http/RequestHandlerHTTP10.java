package http;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.Socket;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.SimpleTimeZone;

import burp.Tab_SimpleHttpServer;

/**
 * A Handler for the HTTP protocol.
 */
abstract class RequestHandlerHTTP10 extends RequestHandler {

	final static String RFC1123_DATE_PATTERN = "EEE, dd MMM yyyy HH:mm:ss 'GMT'";

	public RequestHandlerHTTP10(Socket socket) {
		super(socket);
	}

	protected abstract void handle(HTTPRequest request, HTTPResponse response) throws IOException;

	@Override
	protected void handle(Socket socket) throws IOException, SimpleWebServerException {
		HTTPRequest request = this.getHTTPRequest(socket);
		HTTPResponse response = new HTTPResponse(socket);
		
		DateFormat rfc1123_DateFormat = new SimpleDateFormat(RFC1123_DATE_PATTERN, Locale.US);
		rfc1123_DateFormat.setTimeZone(new SimpleTimeZone(0, "GMT"));
		String date = rfc1123_DateFormat.format(new Date());
		response.setHeader(HTTPResponse.Header.Date, date);
		
		// Set Content-Type
		String contentType;
		if (Tab_SimpleHttpServer.getContentTypeCheckbox().isSelected()) {
			contentType = Tab_SimpleHttpServer.getContentTypeTextField().getText().trim();
		} else {
			contentType = Tab_SimpleHttpServer.getContentTypeCombo().getSelectedItem().toString().trim();
		}
		response.setContentType(contentType);
		response.setHeader(HTTPResponse.Header.Server, "BurpHTTPServer/1.0");

		response.setHeader(HTTPResponse.Header.Connection, "close");
		if (HTTPRequest.Version.HTTP11.toString().equals(request.getHTTPVersion())) {
			response.setHTTPVersion(HTTPRequest.Version.HTTP10);
		} else if (!HTTPRequest.Version.HTTP10.toString().equals(request.getHTTPVersion())) {
			throw new SimpleWebServerException(
					"Don't know how to answer HTTP requests with this version header: " 
					+ request.getHTTPVersion());
		}

		this.handle(request, response);

		// Return request info
		String respMsg = socket.getInetAddress().getHostAddress() 
				+ " [" + new Date().toString() + "] " 
				+ request.getMethod()
				+ " " + request.getHTTPVersion() 
				+ " " 
				+ request.getURI() 
				+ " " 
				+ response.getStatusCode();
		
		Tab_SimpleHttpServer.msg(respMsg);

		response.close();
	}

	private HTTPRequest getHTTPRequest(Socket socket) throws IOException, SimpleWebServerException {
		HTTPRequest r = new HTTPRequest();
		InputStream is = socket.getInputStream();
		Reader reader = new InputStreamReader(is);
		BufferedReader bufferedReader = new BufferedReader(reader);
		String httpRequestLine = "";
		httpRequestLine = bufferedReader.readLine();
		if (httpRequestLine == null) {
			throw new SimpleWebServerException("No (or not enough) data received (within timeout)");
		}

		try {
			String[] httpRequestLineSplitArray = httpRequestLine.split(" ");
			r.method = httpRequestLineSplitArray[0];
			r.URI = httpRequestLineSplitArray[1];
			r.HTTPVersion = httpRequestLineSplitArray[2];
		} catch (Exception ex) {
			throw new SimpleWebServerException(
					"HTTP Request Line (1st line) invalid, should be 'VERB URI VERSION' and not '" 
					+ httpRequestLine + "'; see RFC 2616, Section 5", ex);
		}

		while (bufferedReader.ready()) {
			String line = bufferedReader.readLine();
			if (line.length() == 0) {
				break;
			}
			int httpRequestHeaderKeySeparatorPos = line.indexOf(':');
			String httpRequestHeaderKey = line.substring(0, httpRequestHeaderKeySeparatorPos);
			String httpRequestHeaderValue = line.substring(httpRequestHeaderKeySeparatorPos + 1, line.length());
			httpRequestHeaderValue = httpRequestHeaderValue.trim(); // RFC 2616 Section 4.2

			r.headers.put(httpRequestHeaderKey, httpRequestHeaderValue);
		}

		// Test if Header/Body delimiter code here works
		StringBuffer bodySB = new StringBuffer(1024);
		while (bufferedReader.ready()) {
			String line = "";
			do {
				line = bufferedReader.readLine();
			} while (line.length() == 0);
			
			bodySB.append(line);
			bodySB.append('\n');
		}
		r.body = bodySB.toString();

		return r;
	}
}
