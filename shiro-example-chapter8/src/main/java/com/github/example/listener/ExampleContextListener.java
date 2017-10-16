package com.github.example.listener;

import java.util.EventListener;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class ExampleContextListener implements ServletContextListener {

	@Override
	public void contextInitialized(ServletContextEvent sce) {
		
		ServletContext context = sce.getServletContext();
	}

	@Override
	public void contextDestroyed(ServletContextEvent sce) {
		// TODO Auto-generated method stub
		
	}

}
