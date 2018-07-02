package http;

class SimpleWebServerException extends Exception {

	private static final long serialVersionUID = -8775183699138464297L;

	public SimpleWebServerException() {
		super();
	}

	public SimpleWebServerException(String reason) {
		super(reason);
	}

	public SimpleWebServerException(String reason, Throwable nestedReason) {
		super(reason, nestedReason);
	}

	public SimpleWebServerException(Throwable nestedReason) {
		super(nestedReason);
	}
}
