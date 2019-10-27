package srcProyecto;

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;
import uniandes.gload.examples.clientserver.generator.ClientServerTask;

public class Generator {

	/**
	 * Load Generator service
	 */
	private LoadGenerator generator;

	/**
	 * Constructor de un nuevo generador
	 */
	public Generator(){
		Task work = createTask();
		int numberOfTasks = 100;
		int gapsBetweenTasks = 1000;
		generator = new LoadGenerator("Prueba Cliente-Servidor", numberOfTasks, work, gapsBetweenTasks);
		generator.generate();
	}

	/**
	 * Ayuda para construir un task
	 * @return Task 
	 */
	private Task createTask(){
		return new ClientServerTask();
	}

	/**
	 * Inicia la aplicación
	 * @param args
	 */
	public static void main(String[] args) {

		@SuppressWarnings("unused")
		Generator gen = new Generator();
	}

}
