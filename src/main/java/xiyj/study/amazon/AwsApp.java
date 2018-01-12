package xiyj.study.amazon;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormatSymbols;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Scanner;

import javax.net.ssl.SSLContext;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

public class AwsApp {
	public static void p(String msg) {
		System.out.println(msg);
	}

	public static String _awsAccessKey = null;
	public static String _awsSecretKey = null;

	// example url : GET
	// /2013-04-01/hostedzone/Id/rrset?identifier=StartRecordIdentifier&maxitems=MaxItems&name=StartRecordName&type=StartRecordType
	// HTTP/1.1
	public static void listResourceRecordSets() throws Exception {
		AWS aws = new AWS(true, true);
		URL url = new URL("https://route53.amazonaws.com/2013-04-01/hostedzone/Z3MNENJUQP841O"
				+ "" // ?type=SRV
		);
		InputStream in = null;
		Map<String, String> headers = new HashMap<>();
		HttpURLConnection conn = aws.doRest(AWS.HttpMethod.GET, url, in, headers);

		Scanner s = new Scanner(conn.getInputStream()).useDelimiter("\\A");
		p("response content : " + (s.hasNext() ? s.next() : ""));
		// Document xmlDoc = aws.parseToDocument(conn.getInputStream());

	}

	// using httpClient
	public static void listResourceRecordSets2() throws Exception {
		AWS aws = new AWS(true, true);

		// URL url = new URL("https://route53.amazonaws.com/2012-02-29/hostedzone/Z3MNENJUQP841O");
		URL url = new URL("https://route53.amazonaws.com/2012-02-29/hostedzone");
		p("\nacceptAll, url : " + url);
		try {
			SSLContext sslContext = new SSLContextBuilder()
					.loadTrustMaterial(null, (certificate, authType) -> true).build();

			try (CloseableHttpClient client = HttpClients.custom().setSSLContext(sslContext)
					.setSSLHostnameVerifier(new NoopHostnameVerifier()).build()) {
				HttpGet httpGet = new HttpGet(url.toURI());

				Map<String, String> headers = new HashMap<>();

				String signature = aws.generateRestSignature(AWS.HttpMethod.GET, url, headers);
				// headers.put("Authorization", "AWS " + aws.awsAccessKey + ":" + signature);
				headers.put("Authorization", String.format(
						"AWS3-HTTPS AWSAccessKeyId=%s,Algorithm=HmacSHA256,Signature=%s",
						aws.awsAccessKey, signature));
				// Ensure the Host header is always set
				headers.put("Host", url.getHost());

				for (Entry<String, String> e : headers.entrySet()) {
					p("set header, " + e.getKey() + " : " + e.getValue());
					httpGet.setHeader(e.getKey(), e.getValue());
				}

				// httpGet.setHeader("Accept", "application/xml");
				HttpResponse response = client.execute(httpGet);

				p("response status code : " + response.getStatusLine().getStatusCode());
				for (Header e : response.getAllHeaders()) {
					p("response header " + e.getName() + " : " + e.getValue());
				}

				Scanner s = new Scanner(response.getEntity().getContent()).useDelimiter("\\A");
				p("response content : " + (s.hasNext() ? s.next() : ""));
			}
		} catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException
				| IOException e) {
			p(e.toString());
			e.printStackTrace(System.out);
		}

	}

	public static void testS3_2() throws Exception {
		S3 s3 = new S3(true, true);

		URL url = s3.generateS3Url("", "", s3.EMPTY_STRING_MAP);
		// HttpURLConnection conn = doRest(HttpMethod.GET, url);
		// Document xmlDoc = parseToDocument(conn.getInputStream());

		// URL url = new
		// URL("https://route53.amazonaws.com/2013-04-01/hostedzone/Z3MNENJUQP841O");
		p("\nacceptAll, url : " + url.toString());
		try {
			SSLContext sslContext = new SSLContextBuilder()
					.loadTrustMaterial(null, (certificate, authType) -> true).build();

			try (CloseableHttpClient client = HttpClients.custom().setSSLContext(sslContext)
					.setSSLHostnameVerifier(new NoopHostnameVerifier()).build()) {
				HttpGet httpGet = new HttpGet(url.toURI());

				Map<String, String> headers = new HashMap<>();

				String signature = s3.generateRestSignature(AWS.HttpMethod.GET, url, headers);
				headers.put("Authorization", "AWS " + s3.awsAccessKey + ":" + signature);
				// Ensure the Host header is always set
				headers.put("Host", url.getHost());

				for (Entry<String, String> e : headers.entrySet()) {
					p("set header, " + e.getKey() + " : " + e.getValue());
					httpGet.setHeader(e.getKey(), e.getValue());
				}

				// httpGet.setHeader("Accept", "application/xml");
				HttpResponse response = client.execute(httpGet);

				p("response status code : " + response.getStatusLine().getStatusCode());
				for (Header e : response.getAllHeaders()) {
					p("response header " + e.getName() + " : " + e.getValue());
				}

				Scanner s = new Scanner(response.getEntity().getContent()).useDelimiter("\\A");
				String xml = s.hasNext() ? s.next() : "";
				p("response content : " + xml);

				Document xmlDoc = s3.parseToDocument(xml);

				for (Node node : s3.xpathToNodeList("//Buckets/Bucket", xmlDoc)) {
					p("bucket.name = " + s3.xpathToContent("Name", node));
					p("bucket.creationDate = " + s3.xpathToContent("CreationDate", node));
				}

			}
		} catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException
				| IOException e) {
			p(e.toString());
			e.printStackTrace(System.out);
		}

	}

	public static void testS3() throws Exception {
		S3 s3 = new S3(true, true);

		System.out.println(s3.listBuckets());

		System.out.println(s3.createBucket("test.location3", S3.BucketLocation.EU));
		System.out.println(s3.listBuckets());

		System.out.println(s3.deleteBucket("test.location3"));
		System.out.println(s3.listBuckets());
	}

	// before run it, setup environment variable
	// AWS_ACCESS_KEY
	// AWS_SECRET_KEY
	public static void main(String[] args) throws Exception {
		// listResourceRecordSets();
		listResourceRecordSets2();

		// testS3();
		// testS3_2();
		{
			Date date1 = new Date();
			System.out.println("default date : " + date1);
			SimpleDateFormat iso8601DateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
			p("iso8601 date : " + iso8601DateFormat.format(date1));
			Locale locale = new Locale("en", "CA");
			DateFormatSymbols dateFormatSymbols = new DateFormatSymbols(locale);
			SimpleDateFormat rfc822DateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", locale);
			p("rfc822 date : " + rfc822DateFormat.format(date1));
		}
	}

}
