package xiyj.study.concurrency;

import java.io.File;
import java.io.IOException;
import java.util.Scanner;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

public class BlockingQueueApp {
	public static void p(String msg) {
		System.out.println(msg);
	}

	public static final int FILE_QUEUE_SIZE = 10;
	public static final int SEARCH_THREADS = 100;
	public static final File DUMMY = new File("");
	public static BlockingQueue<File> queue = new ArrayBlockingQueue<>(FILE_QUEUE_SIZE);

	public static void main(String[] args) {
		test();
	}

	public static void test() {
		try (Scanner in = new Scanner(System.in)) {
			System.out.print("Enter base directory (e.g. /opt/jdk1.8.0/src): ");
			String directory = in.nextLine();
			System.out.print("Enter keyword (e.g. volatile): ");
			String keyword = in.nextLine();

			Runnable enumerator = () -> {
				try {
					enumerate(new File(directory));
					queue.put(DUMMY);
				} catch (InterruptedException e) {
				}
			};

			new Thread(enumerator).start();
			for (int i = 1; i <= SEARCH_THREADS; i++) {
				final Integer id = i;
				Runnable searcher = () -> {
					try {
						p("Runnable " + id + " entering...");
						boolean done = false;
						while (!done) {
							File file = queue.take();
							if (file == DUMMY) {
								queue.put(file);
								done = true;
							} else {
								p("Runnable " + id + " get file : " + file.getName());
								search(file, keyword);
							}
						}
					} catch (IOException e) {
						e.printStackTrace();
					} catch (InterruptedException e) {
					}
					p("Runnable " + id + " leaving...");
				};
				new Thread(searcher).start();
			}
		}
	}

	/**
	 * Recursively enumerates all files in a given directory and its subdirectories.
	 * 
	 * @param directory
	 *            the directory in which to start
	 */
	public static void enumerate(File directory) throws InterruptedException {
		File[] files = directory.listFiles();
		for (File file : files) {
			if (file.isDirectory())
				enumerate(file);
			else
				queue.put(file);
			p("put file : " + file.getName() + ", queue size : " + queue.size());
		}
	}

	/**
	 * Searches a file for a given keyword and prints all matching lines.
	 * 
	 * @param file
	 *            the file to search
	 * @param keyword
	 *            the keyword to search for
	 */
	public static void search(File file, String keyword) throws IOException {
		try (Scanner in = new Scanner(file, "UTF-8")) {
			int lineNumber = 0;
			while (in.hasNextLine()) {
				lineNumber++;
				String line = in.nextLine();
				if (line.contains(keyword))
					System.out.printf("%s:%d:%s%n", file.getPath(), lineNumber, line);
			}
		}
	}
}
