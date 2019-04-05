package srcProyecto;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Scanner;
import java.security.cert.X509Certificate;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class Cliente {

	static Socket s;

	public final static String ALGORTIMO1 = "Blowfish";

	public final static String ALGORITMO2 = "RSA";

	public final static String ALGORITMO3 = "HMACSHA256";


	public static void main(String[] args) {
		// TODO Auto-generated method stub

		try {

			KeyPairGenerator generadorLlaves = KeyPairGenerator.getInstance(ALGORITMO2);
			generadorLlaves.initialize(1024);
			KeyPair keyPair = generadorLlaves.generateKeyPair();
//			PublicKey publica = keyPair.getPublic();
//			PrivateKey privada = keyPair.getPrivate();

//			SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy");
//			Date notBefore = sdf.parse("01/04/2019");
//			Date notAfter = sdf.parse("21/12/2019");
//			
			
//			Date notBefore = new Date();
//			Date notAfter = new Date(notBefore.getTime() + 15 * 86400000l);
//			
//			SubjectPublicKeyInfo infoPublica = SubjectPublicKeyInfo.getInstance(publica.getEncoded());			
			s = new Socket("localhost", 6790);

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

				sendMessage = mensaje + ":" + ALGORTIMO1 + ":" + ALGORITMO2 + ":" + ALGORITMO3 + "\n";

				bw.write(sendMessage);
				bw.flush();
				System.out.println("Message sent to the server : "+sendMessage);   
				message = br.readLine();
				System.out.println("Message received from the server : " +message);

				if(message.equals("OK"))
				{
//					X500Name owner = new X500Name("CN=ncobosjftorresp");
//					X500Name name2 = new X500Name("CN=Nombre2");
//					X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(owner, new BigInteger(64, new SecureRandom()), notBefore, notAfter, name2, infoPublica );
////					X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(owner, new BigInteger(64, new SecureRandom()),notBefore, notAfter, owner,publica);
//					ContentSigner signer =new JcaContentSignerBuilder("SHA1WithRSA").setProvider(new BouncyCastleProvider()).build(privada);
//					X509CertificateHolder holder = certificateBuilder.build(signer);
//					java.security.cert.X509Certificate cert = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);
					X509Certificate cert = generateCertificate(keyPair, "");
					byte[] certificadoEnBytes = cert.getEncoded( );
					String certificadoEnString = DatatypeConverter.printHexBinary(certificadoEnBytes);
					sendMessage=certificadoEnString;
					bw.write(sendMessage);
					bw.flush();
					System.out.println("Message sent to the server : "+sendMessage);   
					message = br.readLine();
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
		catch (OperatorCreationException e) {
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
	
	private static X509Certificate generateCertificate (KeyPair llaves, String subject) throws OperatorCreationException, CertificateException
	{
		Provider bcp = new BouncyCastleProvider();
		Security.addProvider(bcp);
		
		long tiempo = System.currentTimeMillis();
		Date inicio = new Date(tiempo);
		
		X500Name owner = new X500Name("CN= ncobosjftorresp");
		
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
		
		System.out.println(certificado.getPublicKey().toString());
		return certificado;
	}

}
