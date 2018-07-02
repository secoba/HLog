package http;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import burp.Tab_SimpleHttpServer;

/**
 * A Server that allows multiple concurrent Worker threads. This implementation is based on the JDK 5.0 java.util.concurrent.*
 */
class ServerMultiThreadedWorkers extends ServerSingleThreadedWorker {

	private final ExecutorService pool;

	public ServerMultiThreadedWorkers(int port, int timeout, int threads, RequestHandlerFactory requestHandlerFactory) {
		super(port, timeout, requestHandlerFactory);
		pool = Executors.newFixedThreadPool(threads);
	}

	@Override
	protected void handle(RequestHandler handler) {
		assert handler != null;
		pool.execute(handler);
	}

	@Override
	public void terminate() {
		Tab_SimpleHttpServer.msg("Stopping HTTP Server");
		super.terminate();
		pool.shutdownNow();
		try {
			pool.awaitTermination(3, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			// Fine, whatever; main thing is that we stopped.
		}
		assert pool.isTerminated();
		assert pool.isShutdown();
	}
}
