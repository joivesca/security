package com.onndoo.security.listener;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;

@WebListener
public class PolicyRegistrationListener implements ServletContextListener {

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        //PolicyFactory policyFactory = PolicyFactory.getPolicyFactory();
        //policyFactory.setPolicy(new TestPolicy(policyFactory.getPolicy()));
    }

}