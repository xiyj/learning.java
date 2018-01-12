package xiyj.study;

import java.io.File;
import java.text.DateFormat;
import java.text.DateFormatSymbols;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class StringApp {
	public static void p(String s) {
		System.out.println(s);
	}

	public static void main(String[] args) {
		// test01();
		// regexMatch();
		// regexSearch();
		// testNumParsing();
		// testSplitAndSpace();
		// testSplit();
		// testSpace();
		testNull();
	}

	public static void test01() {
		String s = "hello, 		, world 	and here no		matt";
		p("string : " + s);
		p("remove space \\\\s: " + s.replaceAll("\\s", ""));
		p("remove space ' ': " + s.replaceAll(" ", ""));

		p("match Worl : " + s.matches(".*Worl.*"));
		p("match (?i)Worl : " + s.matches(".*(?i)Worl.*"));

		p("%s_ test : " + String.format("xx %s_xx", "hello"));
	}

	public static void regexMatch() {
		try {
			String str = "RefId=18-Dec-2017 12:20";
			Pattern regex = Pattern.compile("RefId=((\\d{2})-(\\w{3})-(\\d{4}) (\\d{2}):(\\d{2}))");
			p("string : " + str);
			p("regex : " + regex.toString());
			Matcher m = regex.matcher(str);
			if (m.matches()) {
				p("match group 0 : " + m.group(0));
				p("match group 1 : " + m.group(1));
				p("match group 2 : " + m.group(2));
				p("match group 3 : " + m.group(3));
				p("match group 4 : " + m.group(4));
				p("match group 5 : " + m.group(5));
				p("match group 6 : " + m.group(6));

				Locale locale = new Locale("en", "CA");
				DateFormatSymbols dateFormatSymbols = new DateFormatSymbols(locale);
				DateFormat df = new SimpleDateFormat("dd-MMM-yyyy HH:mm", dateFormatSymbols);
				Date d = df.parse(m.group(1));
				p("parse date : " + d.toString());
			} else
				p("not match");

		} catch (ParseException e) {
			e.printStackTrace();
		}

		{
			String str = "20171204_1205";
			p(str + " match \"\\\\d{8}.*\" : " + str.matches("\\d{8}.*"));
			String arcDir = str.substring(0, 6) + File.separator + str.substring(6, 8);
			p("arcDir should be " + arcDir);
		}
	}

	public static void regexSearch() {
		String str = "abcdefghijklmnopq";
		Pattern regex = Pattern.compile("e(\\w{3})");
		p("string : " + str);
		p("regex : " + regex.toString());
		Matcher m = regex.matcher(str);
		if (m.find()) {
			p("found : " + m.group(0) + ", " + m.group(1));
		}
	}

	public static void testNumParsing() {
		p("00 to int : " + Integer.parseInt("00"));
		p("01 to int : " + Integer.parseInt("01"));

		{
			// sample record : 00:05,72067
			String s = "01:25";
			p(s + " first part : " + Integer.parseInt(s.substring(0, 2)));
			p(s + " second part : " + Integer.parseInt(s.substring(3, 5)));

			String n = null;
			p("null plus something : " + n + "yes");
		}
	}

	public static void testSplitAndSpace() {
		{
			String s = "|A|BB|CCC||||";
			p("string to split : " + s);

			p("normal split");
			String[] words = s.split("|");
			for (String string : words) {
				System.out.println(">" + string + "<");
			}

			p("normal split with -1");
			words = s.split("|", -1);
			for (String string : words) {
				System.out.println(">" + string + "<");
			}

			p("\\\\ split with -1");
			words = s.split("\\|", -1);
			for (String string : words) {
				System.out.println("#" + string + "<");
			}
		}

		{
			String s = ",A,BB,CCC,,,,";
			p("string to split : " + s);

			p("normal split");
			String[] words = s.split(",");
			for (String string : words) {
				System.out.println(">" + string + "<");
			}

			p("normal split with -1");
			words = s.split(",", -1);
			for (String string : words) {
				System.out.println(">" + string + "<");
			}

			p("\\\\ split with -1");
			words = s.split("\\,", -1);
			for (String string : words) {
				System.out.println("#" + string + "<");
			}
		}

		{
			String s = " 12,	,		,as";
			p("replace \\s as : " + s.replaceAll("\\s", "x"));
			p("replace \\S as : " + s.replaceAll("\\S", "x"));
			p("-1 is :" + -1);
			String[] words = s.split("\\,", -1);
			for (String string : words) {
				System.out.println("#" + string + "<");
			}
		}
	}

	public static void testSplit() {
		String s = "1,,3,,5,,,";
		System.out.println("test string : " + s);
		{
			String[] ss = s.split(",");
			System.out.println("split , : " + String.join("|", ss));

			ss = s.split(",", 3);
			System.out.println("split , 3 : " + String.join("|", ss));

			ss = s.split(",", 6);
			System.out.println("split , 6 : " + String.join("|", ss));

			ss = s.split(",", -1);
			System.out.println("split , -1 : " + String.join("|", ss));
		}
	}

	public static void testSpace() {
		String s;

		s = "hello world";
		p("search space in string : " + s);
		if (s.matches(".*\\s.*"))
			p("yes");

		s = "helloworld";
		p("search space in string : " + s);
		if (s.matches(".*\\s.*"))
			p("yes");
		else
			p("no");

	}
	
	public static void testNull() {
		String s = "hello";
		String t = null;
		p("null + s : "  + (null + s));
	}
}
