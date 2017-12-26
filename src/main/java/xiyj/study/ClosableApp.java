package xiyj.study;

import java.io.Closeable;
import java.io.IOException;
import java.util.function.Supplier;

public class ClosableApp {

	public static String p(String msg) {
		System.out.println(msg);
		return msg;
	}

	public static void main(String[] args) throws Exception {
		p("closable and related code");

		test01();
	}

	public static void test01() throws Exception {

		p("closable + using");

		AutoCloseable c = new AutoCloseable() {
			@Override
			public void close() {
				p("close()");
			}
		};

		try (AutoCloseable cc = c) {
			p("within try() block 1");
			p("this is the most simple and straight forward way");
		}

		try (AutoCloseable cc = new AutoCloseable() {
			@Override
			public void close() {
				p("inline close()");
			}
		}) {
			p("within try() block 2");
		}

		p("cuz ctro not throw, so this is the better solution, using Supplier (or Function<T,R>)");

		Supplier<AutoCloseable> createInput = () -> {
			p("Lambda for get(), may using try to catch exception");
			return new AutoCloseable() {
				@Override
				public void close() throws Exception {
					p("close within lambda");
				}
			};
		};

		try (AutoCloseable cc = createInput.get()) {
			p("try with lambda");
		}

	}
}
