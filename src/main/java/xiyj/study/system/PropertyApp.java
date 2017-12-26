package xiyj.study.system;

public class PropertyApp {
	public static void p(String s) { System.out.println(s); }

	public static void main(String[] args) {
		p("set system property as null");
		System.setProperty("javax.net.ssl.trustStore", null);
	}

}
