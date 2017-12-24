package gosigma.study;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.text.SimpleDateFormat;
import java.util.Scanner;

public class FileApp {
	public static void p(String s) {
		System.out.println(s);
	}

	public static void main(String[] args) throws IOException {
		// testTimestamp();
		testURLStream();
	}

	public static void testTimestamp() {
		File file = new File("c:\\tmp\\NgLog4j.prop.log");
		System.out.println("file modified at : " + file.lastModified());

		SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");
		System.out.println("to date : " + sdf.format(file.lastModified()));
	}

	public static void testURLStream() throws IOException {
		URLClassLoader cl = (URLClassLoader) FileApp.class.getClassLoader();
		String file = "logback.xml";
		URL url = cl.getResource(file);
		p(file + "'s url : " + url.toString());

		InputStream in = url.openStream();
		p("url input stream : " + in.toString());
		Scanner s = new Scanner(in).useDelimiter("\\A");
		p("content : " + (s.hasNext() ? s.next() : ""));
	}
}
