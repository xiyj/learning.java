package xiyj.study.amazon;

public class AwsApp {
	public static void p(String msg) {
		System.out.println(msg);
	}
	
	public static String _awsAccessKey = null;
	public static String _awsSecretKey = null;

	public static void listResourceRecordSets() {
		AWS aws = new AWS(true, true);
	}

	public static void main(String[] args) {
		listResourceRecordSets();
	}
}
