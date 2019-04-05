package srcProyecto;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class ClienteCS {
	
	static Socket s;

	public final static String ALGORITMO1 = "Blowfish";

	public final static String ALGORITMO2 = "RSA";

	public final static String ALGORITMO3 = "HMACSHA256";

	public static void main(String[] args) {


		try {

			KeyPairGenerator generadorLlaves = KeyPairGenerator.getInstance(ALGORITMO2);
			generadorLlaves.initialize(1024);
			KeyPair keyPair = generadorLlaves.generateKeyPair();
			
			KeyGenerator keygen = KeyGenerator.getInstance(ALGORITMO1);
			keygen.init(128);
			SecretKey secretKey = keygen.generateKey();
			
			PublicKey llavePublica = keyPair.getPublic();
			PrivateKey llavePrivada = keyPair.getPrivate();
			
			s = new Socket("localhost", 6790);
			PrintWriter escritor = new PrintWriter(s.getOutputStream(), true);

			BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));

			OutputStream os = s.getOutputStream();
			OutputStreamWriter osw = new OutputStreamWriter(os);
			BufferedWriter bw = new BufferedWriter(osw);

			String mensaje = "HOLA";

			String sendMessage = mensaje + "\n";
			bw.write(sendMessage);
			bw.flush();
			System.out.println("Message sent to the server : "+sendMessage);

			//Get the return message from the server
			InputStream is = s.getInputStream();
			InputStreamReader isr = new InputStreamReader(is);
			BufferedReader br = new BufferedReader(isr);
			String message = br.readLine();
			System.out.println("Message received from the server : " +message);

			if(message.equals("OK"))
			{
				mensaje = "ALGORITMOS";	

				sendMessage = mensaje + ":" + ALGORITMO1 + ":" + ALGORITMO2 + ":" + ALGORITMO3 + "\n";

				bw.write(sendMessage);
				bw.flush();
				System.out.println("Message sent to the server : "+sendMessage);

				message = br.readLine();
				System.out.println("Message received from the server : " +message);

				if(message.equals("OK"))
				{

					X509Certificate cert = null;
					try {
						cert = generateCertificate(keyPair);
					} catch (OperatorCreationException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}

					byte[] certificadoEnBytes = cert.getEncoded( );
					String certificadoEnString = DatatypeConverter.printHexBinary(certificadoEnBytes);
					sendMessage = certificadoEnString;
					//					bw.write(sendMessage);
					//					bw.flush();
					escritor.println(sendMessage);
					System.out.println("Message sent to the server : "+sendMessage);   

					message = br.readLine();
					String certificadoS = message;
					System.out.println("Message received from the server : " +message);
					
					byte[] certificadoP = DatatypeConverter.parseHexBinary(certificadoS);
					
					CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
					
					X509Certificate certificadoF = (X509Certificate)certFactory.generateCertificate(new ByteArrayInputStream(certificadoP));
					
					PublicKey llavePs = certificadoF.getPublicKey();
					
					byte[] sK = secretKey.getEncoded();
					
					String textoDefinitivo = DatatypeConverter.printHexBinary(sK);
					
					byte[] cifrado = cifrar(llavePs, textoDefinitivo, ALGORITMO2);
					
					String cadena3 = DatatypeConverter.printHexBinary(cifrado);
					
					sendMessage = cadena3;
					
					escritor.println(sendMessage);
					System.out.println("Message sent to the server : "+sendMessage);   

					message = br.readLine();
					System.out.println("Message received from the server : " +message);
					
					String datos1 = "1;41 24.2028,2 10.4418";
					
					sendMessage = "OK";
					
					escritor.println(sendMessage);
					System.out.println("Message sent to the server : "+sendMessage); 
					
					byte[] cifrado2 = cifrar(secretKey, datos1, ALGORITMO1);
					
					String cadena4 = DatatypeConverter.printHexBinary(cifrado2);
					
					sendMessage = cadena4;
					
					escritor.println(sendMessage);
					System.out.println("Message sent to the server : "+sendMessage); 
					
					Mac hmac = Mac.getInstance("HmacSHA256");
					
					try {
						hmac.init(new SecretKeySpec(secretKey.getEncoded(), "HmacSHA256"));
					} catch (InvalidKeyException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					
					byte[] datosH = DatatypeConverter.parseHexBinary(datos1);
					
					byte[] resultado = hmac.doFinal(datosH);
					
					String cadena5 = DatatypeConverter.printHexBinary(resultado);
					
					sendMessage = cadena5;
					
					escritor.println(sendMessage);
					System.out.println("Message sent to the server : "+sendMessage);   
					
					message = br.readLine();
					System.out.println("Message received from the server : " +message);
					
				}
			}



			s.close();

		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	private static X509Certificate generateCertificate (KeyPair llaves) throws OperatorCreationException, CertificateException
	{
		Provider bcp = new BouncyCastleProvider();
		Security.addProvider(bcp);

		long tiempo = System.currentTimeMillis();
		Date inicio = new Date(tiempo);

		X500Name owner = new X500Name("CN=localhost");

		BigInteger serial = new BigInteger(Long.toString(tiempo));

		Calendar calendario = Calendar.getInstance();
		calendario.setTime(inicio);
		calendario.add(Calendar.YEAR, 1);
		Date fin = calendario.getTime();

		String algoritmo = "SHA256WithRSA";
		SubjectPublicKeyInfo infoPublica = SubjectPublicKeyInfo.getInstance(llaves.getPublic().getEncoded());	
		X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(owner, serial, inicio, fin, owner, infoPublica);

		ContentSigner signer =new JcaContentSignerBuilder(algoritmo).setProvider(bcp).build(llaves.getPrivate());
		X509CertificateHolder holder = certificateBuilder.build(signer);

		X509Certificate certificado = new JcaX509CertificateConverter().getCertificate(holder);
		return certificado;
	}
	
	public static byte[] cifrar(Key key, String texto, String algoritmo){
		byte[] textoCifrado;
		
		try {
			Cipher cifrador = Cipher.getInstance(algoritmo);
			byte[] textoClaro = texto.getBytes();
			
			cifrador.init(Cipher.ENCRYPT_MODE, key);
			textoCifrado = cifrador.doFinal(textoClaro);
			
			return textoCifrado;
			
		} catch (Exception e) {
			System.out.println("Excpecion: " + e.getMessage());
			return null;
		}	
	}

}
