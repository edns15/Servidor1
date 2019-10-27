package srcProyecto;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.operator.OperatorCreationException;

public class ClienteCS 
{
	/**
	 * Socket para generar la comunicación con el servidor
	 */
	static Socket s;

	/**
	 * Constante que representa la cadena del algortimo Blowfish
	 */
	public final static String ALGORITMO1 = "Blowfish";

	/**
	 * Constante que representa la cadena del algortimo RSA
	 */
	public final static String ALGORITMO2 = "RSA";

	/**
	 * Constante que representa la cadena del algortimo HMACSHA256
	 */
	public final static String ALGORITMO3 = "HMACSHA256";

	/**
	 * Metodo main que ejecuta el protocolo de comunicacion del cliente y recibe las respuestas del Servidor. 
	 * @param args
	 */
	public static void main(String[] args) 
	{
		try 
		{	
			//GENERAR LAS LLAVES ASIMETRICAS CON EL ALGORITMO RSA
			KeyPairGenerator generadorLlaves = KeyPairGenerator.getInstance(ALGORITMO2);
			generadorLlaves.initialize(1024);
			KeyPair keyPair = generadorLlaves.generateKeyPair();
			//OBTENCION DE LLAVE PUBLICA Y PRIVADA
			PublicKey llavePublica = keyPair.getPublic();
			PrivateKey llavePrivada = keyPair.getPrivate();
			//GENERAR LA LLAVE SIMETRICA
			KeyGenerator keygen = KeyGenerator.getInstance(ALGORITMO1);
			SecretKey secretKey = keygen.generateKey();
			//ESCRITOR
			s = new Socket("localhost", 6790);

			PrintWriter escritor = new PrintWriter(s.getOutputStream(), true);
			//MEDIO DE RECEPCION
			InputStream is = s.getInputStream();
			InputStreamReader isr = new InputStreamReader(is);
			BufferedReader br = new BufferedReader(isr);
			//ETAPA 1 ENVIO DE HOLA
			String mensaje = "HOLA";

			String sendMessage = mensaje;
			escritor.println(mensaje);
			
			System.out.println("Message sent to the server : "+sendMessage);
			//ETAPA 2 RECEPCION DE OK
			String message = br.readLine();
			System.out.println("Message received from the server : " +message);

			if(message.equals("OK"))
			{
				//ETAPA 3 ENVIO DE ALGORITMOS
				mensaje = "ALGORITMOS";	

				sendMessage = mensaje + ":" + ALGORITMO1 + ":" + ALGORITMO2 + ":" + ALGORITMO3 + "\n";

				escritor.println(sendMessage);
				System.out.println("Message sent to the server : "+sendMessage);

				message = br.readLine();
				System.out.println("Message received from the server : " +message);
				//ETAPA 4 RECEPCION OK/ERROR
				if(message.equals("OK"))
				{

					message = br.readLine();
					String certificado = message;
					System.out.println("Message received from the server : " +message);
					
					byte[] certificadoBytes = DatatypeConverter.parseBase64Binary(certificado);
					
					InputStream in = new ByteArrayInputStream(certificadoBytes);
					
					CertificateFactory f = CertificateFactory.getInstance("X.509");
					
					X509Certificate certificate = (X509Certificate)f.generateCertificate(in);
					
					PublicKey publickey = certificate.getPublicKey();
					
					KeyGenerator keygen1 = KeyGenerator.getInstance(ALGORITMO1);
					
					SecretKey secretKey1 = keygen1.generateKey();
					
					
					String cifrado = DatatypeConverter.printBase64Binary(cifrar(publickey, secretKey1.getEncoded(), ALGORITMO2));
					
					
					String cadena3 = cifrado;

					sendMessage = cadena3;
					//ENVIO DE LA LLAVE SIMETRICA
					escritor.println(cifrado);
					System.out.println("Message sent to the server : "+sendMessage);   
					
					//ENVIO DE RETO
					String reto= "reto";
					escritor.println(reto);
					System.out.println("Message sent to the server : "+reto);   
					//RECEPCION DE RETO CODIFICADO SIMETRICO
					message = br.readLine();
					System.out.println("Llegamos aquí");
					byte[] retoServer = DatatypeConverter.parseBase64Binary(message);
										
					//DECODIFICACION DEL RETO
					byte[] retoDescifrado = descifrar(secretKey, ALGORITMO2, retoServer);
					String retoserver= DatatypeConverter.printBase64Binary(retoDescifrado);
					//COMPARACION DEL RETO ORIGINAL Y EL CODIFICADO
					if(retoserver.equals(reto))
					{
						System.out.println("Message sent to the server : "+"OK");   
						escritor.println("OK");

					}
					else
					{
						System.out.println("Message sent to the server : "+"ERROR");   
						escritor.println("ERROR");
					}
					//ENVIO DEL CC CODIFICADO SIMETRICO
					String cc= "CC CASO2";
					byte[] ccCifrado= cifrar(secretKey,null,ALGORITMO2);
					sendMessage= DatatypeConverter.printBase64Binary(ccCifrado);
					escritor.println(sendMessage);
					System.out.println("Message sent to the server : "+sendMessage);   

					//ENVIO DE LA CLAVE CODIFICADA SIMETRICA
					String clave= "CLAVE CASO2";
					byte[] claveCifrado= cifrar(secretKey,null,ALGORITMO2);
					sendMessage= DatatypeConverter.printBase64Binary(claveCifrado);
					escritor.println(sendMessage);
					System.out.println("Message sent to the server : "+sendMessage);   

					//RECEPCION DEL VALOR CODIFICADO SIMETRICO
					message = br.readLine();
					byte[] valor = DatatypeConverter.parseBase64Binary(message);
					
					//DESCIFRADO DEL VALOR CON LA LLAVE SIMETRICA
					byte[] valorDec= descifrar(secretKey,ALGORITMO2,valor);
					//HMAC AL VALOR 
					byte[] miHmac=getHmac(ALGORITMO2, secretKey, valorDec);
					//RECEPCION DEL HMAC 
					message = br.readLine();
					byte[] hmac = DatatypeConverter.parseBase64Binary(message);
					
					//DESCIFRADO DEL HMAC CON LA LLAVE PUBLICA DEL SERVIDOR
					byte[] hmacDescifrado= descifrar(publickey, ALGORITMO2, hmac);
					
					//COMPARACION DE LOS DOS HMAC
					if(hmacDescifrado.equals(miHmac))
					{
						escritor.println("OK");
						System.out.println("Message sent to the server : "+"OK");   

					}
					else
					{
						escritor.println("ERROR");
						System.out.println("Message sent to the server : "+"ERROR");   

					}
					//ENVIO DE OK/ERROR
					
				}

			}
			s.close();

		}
		catch(Exception e)
		{
			System.out.println(e.getMessage());
		}
		

	}
	/**
	 * Metodo que retorna el texto ingresado en String, como mensaje cifrado en arreglo de bytes utilizando una llave y un algoritmo que pasa por parametro.
	 * @param key Llave utilizada para cifrar el mensaje
	 * @param texto Mensaje a cifrar
	 * @param algoritmo Algoritmo que realiza el cifrado
	 * @return mensaje cifrado en forma de arreglo de bytes
	 */
	public static byte[] cifrar(Key key, byte[] texto, String algoritmo){
		byte[] textoCifrado;

		try {
			Cipher cifrador = Cipher.getInstance(algoritmo);

			cifrador.init(Cipher.ENCRYPT_MODE, key);
			textoCifrado = cifrador.doFinal(texto);

			return textoCifrado;

		} 
		catch (Exception e)
		{
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}	
	}
	
	/**
	 * Metodo que retorna el texto ingresado en arreglo de bytes como un mensaje descifrado en un arreglo de bytes utilizando una llave y un algoritmo que pasa por parametro.
	 * @param key Llave utilizada para descifrar el mensaje
	 * @param texto Mensaje a descifrar
	 * @param algoritmo Algoritmo que realiza el descifrado
	 * @return mensaje descifrado en forma de arreglo de bytes
	 */
	public static byte[] descifrar(Key key, String algoritmo, byte[] texto){
		byte[] textoClaro;

		try {
			Cipher cifrador = Cipher.getInstance(algoritmo);		
			cifrador.init(Cipher.DECRYPT_MODE, key);
			textoClaro = cifrador.doFinal(texto);

		} 
		catch (Exception e) 
		{
			System.out.println("Excpecion: " + e.getMessage());
			return null;
		}	
		return textoClaro;
	}
	/**
	 * Método que obtiene el hash de un mensaje en arreglo de bytes utilizando un algoritmo y llave que pasan por parámetros.
	 * @param algoritmo Algoritmo utilizado para obtener el hash en este caso HMACSHA256
	 * @param llave Llave utilizada para obtener el hash del mensaje
	 * @param buffer mensaje a obtener su hash
	 * @return arreglo de bytes con el hash del mensaje que pasa por parámetro
	 */
	public static byte[] getHmac(String algoritmo, Key llave, byte[] buffer)
	{
		try {
			Mac mac = Mac.getInstance(algoritmo);
			mac.init(llave);
			return mac.doFinal(buffer);
		}
		catch (Exception e)
		{
			System.out.println(e.getMessage());
			return null;
		}
	}
}

//
//X509Certificate cert = null;
//try {
//	cert = generateCertificate(keyPair);
//}
//catch (OperatorCreationException e) 
//{
//	e.printStackTrace();
//}
//
//byte[] certificadoEnBytes = cert.getEncoded( );
//
//String certificadoEnString = DatatypeConverter.printHexBinary(certificadoEnBytes);
//sendMessage = certificadoEnString;
//
//escritor.println(sendMessage);
//System.out.println("Message sent to the server : "+sendMessage);  
