package srcProyecto;

import java.io.BufferedReader;
import java.io.BufferedWriter;
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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
 * Clase que representa la clase Cliente que se comunica con el servidor sin seguridad
 * Autores: Nicolás Cobos - n.cobos@uniandes.edu.co / Juan Felipe Torres - jf.torresp@uniandes.edu.co
 */
public class Cliente {

	/**
	 * Socket para generar la comunicación con el servidor
	 */
	static Socket s;

	/**
	 * Constante que representa la cadena del algortimo Blowfish
	 */
	public final static String ALGORTIMO1 = "Blowfish";

	/**
	 * Constante que representa la cadena del algortimo RSA
	 */
	public final static String ALGORITMO2 = "RSA";

	/**
	 * Constante que representa la cadena del algortimo HMACSHA256
	 */
	public final static String ALGORITMO3 = "HMACSHA256";


	/**
	 * Método main que ejecuta el protocolo de comunicación SIN SEGURIDAD del cliente y recibe las respuestas del Servidor. 
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

		try {

			
			//Generación del par de llaves asiméticas con el algoritmo RSA.
			
			KeyPairGenerator generadorLlaves = KeyPairGenerator.getInstance(ALGORITMO2);
			generadorLlaves.initialize(1024);
			KeyPair keyPair = generadorLlaves.generateKeyPair();
			
			//Creación del socket para la comunicación con el servidor desde el puerto 6790
			s = new Socket("localhost", 6790);
			
			//PrintWriter para el envío de mensajes al servidor
			PrintWriter escritor = new PrintWriter(s.getOutputStream(), true);

			BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));

			OutputStream os = s.getOutputStream();
			OutputStreamWriter osw = new OutputStreamWriter(os);
			BufferedWriter bw = new BufferedWriter(osw);

			//Etapa 1: Seleccionar algoritmos e iniciar sesión
			
			// Primer mensaje enviado "HOLA"
			String mensaje = "HOLA";

			String sendMessage = mensaje + "\n";
			bw.write(sendMessage);
			bw.flush();
			System.out.println("Message sent to the server : "+sendMessage);

			//Proceso de recibir el mensaje del Servidor
			InputStream is = s.getInputStream();
			InputStreamReader isr = new InputStreamReader(is);
			BufferedReader br = new BufferedReader(isr);
			String message = br.readLine();
			System.out.println("Message received from the server : " +message);

			
			//Recepción de mensaje "OK"
			if(message.equals("OK"))
			{
				mensaje = "ALGORITMOS";	

				//Envío de los algoritmos al servidor
				sendMessage = mensaje + ":" + ALGORTIMO1 + ":" + ALGORITMO2 + ":" + ALGORITMO3 + "\n";

				bw.write(sendMessage);
				bw.flush();
				System.out.println("Message sent to the server : "+sendMessage);

				//Recepción de algoritmos por parte del servidor
				message = br.readLine();
				System.out.println("Message received from the server : " +message);

				//Confirmación de algoritmos con mensaje "OK"
				if(message.equals("OK"))
				{

					//Etapa 2: Intercambio de certificados
					
					X509Certificate cert = null;
					
					//Llamado al método que genera el certificado con el par de llaves creadas.
					try {
						cert = generateCertificate(keyPair);
					} catch (OperatorCreationException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}

					//Obtención del certificado codificado como arreglo de bytes
					byte[] certificadoEnBytes = cert.getEncoded( );
					
					//Paso del certificado a un String en hexadecimal
					String certificadoEnString = DatatypeConverter.printHexBinary(certificadoEnBytes);
					sendMessage = certificadoEnString;

					//Envío del certificado al servidor
					escritor.println(sendMessage);
					System.out.println("Message sent to the server : "+sendMessage);   

					//Recepción del certificado del servidor
					message = br.readLine();
					System.out.println("Message received from the server : " +message);
					
					//Envío de la cadena de 128 bytes
					
					byte[] cadena = new byte[128];
					
					//Paso de la cadena de 128 bytes a un String en hexadecimal
					String cadena2 = DatatypeConverter.printHexBinary(cadena);
					
					sendMessage = cadena2;
					
					//Envío de la cadena
					escritor.println(sendMessage);
					System.out.println("Message sent to the server : "+sendMessage);   

					//Recepción de la cadena de 128n bytes del servidor
					message = br.readLine();
					System.out.println("Message received from the server : " +message);
					
					//Etapa 3: Envío de datos
					
					//Creación de la cadena datos con los datos especificados (id, posición)
					String datos1 = "1;41 24.2028,2 10.4418";
					String datos2 = "1;41 24.2028,2 10.4418";
					
					//Inicia proceso de envío de datos con mensaje "OK"
					sendMessage = "OK";
					
					escritor.println(sendMessage);
					System.out.println("Message sent to the server : "+sendMessage);   
					
					//Envío de los datos
					sendMessage = datos1;
					
					escritor.println(sendMessage);
					System.out.println("Message sent to the server : "+sendMessage);   
					
					//Segundo envío de los datos
					sendMessage = datos2;
					
					escritor.println(sendMessage);
					System.out.println("Message sent to the server : "+sendMessage);   
					
					//Recepción de los mismos datos por parte del servidor
					message = br.readLine();
					System.out.println("Message received from the server : " +message);
					
					//FIN DE COMUNICACIÓN SIGUIENDO EL PROTOCOLO
					
				}
			}
			
			//Se cierra el socket para finalizar la conexión
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

	/**
	 * Método que genera el certificado de tipo X509Certificate usando la librería de BouncyCastle. Recibe por parámetro el par de llaves asimétricas propias.
	 * @param llaves Para de llaves asimétricas (pública y privada). != null != "".
	 * @return X059Certificate Certificado del cliente que se envía al Servidor.
	 * @throws OperatorCreationException
	 * @throws CertificateException
	 */
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
}
