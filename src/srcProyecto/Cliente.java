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
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Scanner;
import javax.security.cert.X509Certificate;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x500.X500Name;
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

	public final static String ALGORTIMO3 = "HMACSHA256";


	public static void main(String[] args) {
		// TODO Auto-generated method stub

		try {

			KeyPairGenerator generadorLlaves = KeyPairGenerator.getInstance(ALGORITMO2);
			generadorLlaves.initialize(1024);
			KeyPair keyPair = generadorLlaves.generateKeyPair();
			PublicKey publica = keyPair.getPublic();
			PrivateKey privada = keyPair.getPrivate();

//			SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy");
//			Date notBefore = sdf.parse("01/04/2019");
//			Date notAfter = sdf.parse("21/12/2019");
//			
			
			Date notBefore = new Date();
			Date notAfter = new Date(notBefore.getTime() + 15 * 86400000l);
			
			
			
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

				sendMessage = mensaje + ":" + ALGORTIMO1 + ":" + ALGORITMO2 + ":" + ALGORTIMO3 + "\n";

				bw.write(sendMessage);
				bw.flush();
				System.out.println("Message sent to the server : "+sendMessage);   
				message = br.readLine();
				System.out.println("Message received from the server : " +message);

				if(message.equals("OK"))
				{
					X500Name owner = new X500Name("CN=ncobosjftorresp");
					X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(owner, new BigInteger(64, new SecureRandom()),notBefore, notAfter, owner,publica);
					ContentSigner signer =new JcaContentSignerBuilder("SHA1WithRSA").setProvider(new BouncyCastleProvider()).build(privada);
					X509CertificateHolder holder = certificateBuilder.build(signer);
					java.security.cert.X509Certificate cert = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);

					byte[] certificadoEnBytes = cert.getEncoded( );
					String certificadoEnString = DatatypeConverter.printHexBinary(certificadoEnBytes);
					sendMessage=certificadoEnString;
					bw.write(sendMessage);
					bw.flush();
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

}
