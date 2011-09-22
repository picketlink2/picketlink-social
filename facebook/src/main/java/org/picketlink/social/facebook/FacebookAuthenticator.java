/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors. 
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.picketlink.social.facebook;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.log4j.Logger;

/**
 * Component for sending login requests to Facebook.
 * 
 * @author Anil Saldhana
 * @author Marcel Kolsteren
 * @since May 8, 2011
 */
public class FacebookAuthenticator extends FormAuthenticator 
{ 
   protected static Logger log = Logger.getLogger(FacebookAuthenticator.class);
   protected boolean trace = log.isTraceEnabled();
   
   protected String returnURL;
   protected String clientID;
   protected String clientSecret;
   protected String scope = "email";
   
   protected List<String> roles = new ArrayList<String>();
   
   //Whether the authenticator has to to save and restore request
   protected boolean saveRestoreRequest = true;
   
   private enum STATES { AUTH, AUTHZ, FINISH};
   
   protected FacebookProcessor processor;
     
   public void setReturnURL(String returnURL)
   {
      this.returnURL = returnURL;
   }

   public void setClientID(String clientID)
   {
      this.clientID = clientID;
   }

   public void setScope(String scope)
   {
      this.scope = scope;
   }

   public void setClientSecret(String clientSecret)
   {
      this.clientSecret = clientSecret;
   }
   
   public void setRoleString(String roleStr)
   {
      if(roleStr == null)
         throw new RuntimeException("Role String is null in configuration");
      StringTokenizer st = new StringTokenizer(roleStr, ",");
      while(st.hasMoreElements())
      {
         roles.add(st.nextToken());
      }
   }
   
   public void setSaveRestoreRequest(boolean saveRestoreRequest)
   {
      this.saveRestoreRequest = saveRestoreRequest;
   }

   
   @Override
   public void start() throws LifecycleException
   {
      //Validate the input values
      if(clientID == null)
         throw new LifecycleException("clientID is not provided");
      if(clientSecret == null)
         throw new LifecycleException("clientSecret is not provided");
      if(returnURL == null)
         throw new LifecycleException("returnURL is not provided");
      super.start();
   }

   public boolean authenticate(HttpServletRequest request, HttpServletResponse response, LoginConfig loginConfig) throws IOException
   {
      if(request instanceof Request == false)
         throw new IOException("Not of type Catalina request");
      if(response instanceof Response == false)
         throw new IOException("Not of type Catalina response");
      return authenticate((Request)request, (Response)response, loginConfig);
   }
    
   public boolean authenticate(Request request, Response response, LoginConfig loginConfig) throws IOException
   {  
      if(trace) log.trace("authenticate");
      
      if(processor == null)
         processor = new FacebookProcessor(clientID, clientSecret, scope, returnURL, roles);
      
      HttpSession session = request.getSession();
      String state = (String) session.getAttribute("STATE");
      
      if(trace) log.trace("state="+ state);
      
      if( STATES.FINISH.name().equals(state))
         return true;
      
      if( state == null || state.isEmpty())
      { 
         if (saveRestoreRequest)
         {
            this.saveRequest(request, request.getSessionInternal());
         }
         return processor.initialInteraction(request, response);
      }
      //We have sent an auth request
      if( state.equals(STATES.AUTH.name()))
      {
         return processor.handleAuthStage(request, response);
      }
      
      //Principal facebookPrincipal = null;
      if( state.equals(STATES.AUTHZ.name()))
      {  
         Principal principal = processor.getPrincipal(request, response, context.getRealm());

         if(principal == null)
            throw new RuntimeException("Principal was null. Maybe login modules need to be configured properly.");
         String userName = principal.getName();
         
         request.getSessionInternal().setNote(Constants.SESS_USERNAME_NOTE, userName);
         request.getSessionInternal().setNote(Constants.SESS_PASSWORD_NOTE, "");
         request.setUserPrincipal(principal);

         if (saveRestoreRequest)
         {
            this.restoreRequest(request, request.getSessionInternal());
         }
         register(request, response, principal, Constants.FORM_METHOD, userName, "");
         request.getSession().setAttribute("STATE", STATES.FINISH.name());

         return true;
      }
      return false;
   }
}