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
package org.picketlink.social.auth;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.log4j.Logger;
import org.picketlink.social.facebook.FacebookProcessor;
import org.picketlink.social.openid.auth.OpenIDConsumerAuthenticator;
import org.picketlink.social.openid.auth.OpenIDProcessor;

/**
 * Authenticator that performs authentication with
 * external providers such as facebook, google, yahoo etc.
 * @author Anil Saldhana
 * @since Sep 22, 2011
 */
public class ExternalAuthenticator extends FormAuthenticator
{
   protected static Logger log = Logger.getLogger(OpenIDConsumerAuthenticator.class);
   protected boolean trace = log.isTraceEnabled();
   
   private enum AUTH_PROVIDERS
   {
      FACEBOOK, OPENID;
   }
   
   public static final String AUTH_TYPE = "authType";
 
   protected FacebookProcessor facebookProcessor;
   protected OpenIDProcessor openidProcessor;
   
   protected String returnURL;
   protected String clientID;
   protected String clientSecret;
   protected String facebookScope = "email";

   private String requiredAttributes = "name,email,ax_firstName,ax_lastName,ax_fullName";

   private String optionalAttributes = null;
   
   //Whether the authenticator has to to save and restore request
   protected boolean saveRestoreRequest = true;
   
   private enum STATES { AUTH, AUTHZ, FINISH}; 
   
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
   
   protected List<String> roles = new ArrayList<String>();
   
   public void setReturnURL(String returnURL)
   {
      this.returnURL = returnURL;
   }
   public void setClientID(String clientID)
   {
      this.clientID = clientID;
   }
   public void setClientSecret(String clientSecret)
   {
      this.clientSecret = clientSecret;
   }
   public void setFacebookScope(String facebookScope)
   {
      this.facebookScope = facebookScope;
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

      if(facebookProcessor == null)
         facebookProcessor = new FacebookProcessor(clientID, clientSecret, facebookScope, returnURL, roles);

      if(openidProcessor == null)
         openidProcessor = new OpenIDProcessor(returnURL, requiredAttributes, optionalAttributes);
    
      HttpSession session = request.getSession();
      //Determine the type of service based on request param
      String authType = request.getParameter(AUTH_TYPE);
      if(authType != null && authType.length() > 0)
      {
         //Place it on the session
         session.setAttribute(AUTH_TYPE, authType);
      }
      if(authType == null || authType.length() == 0)
      {
         authType = (String) session.getAttribute(AUTH_TYPE);
      }
      if(authType == null)
      {
         authType = AUTH_PROVIDERS.FACEBOOK.name();
      }
      if(authType != null && authType.equals(AUTH_PROVIDERS.FACEBOOK.name()))
      {
         return processFacebook(request, response);  
      }
      else
      {
         return processOpenID(request, response);
      }
   }
   
   protected boolean processFacebook(Request request, Response response) throws IOException
   {
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
         return facebookProcessor.initialInteraction(request, response);
      }
      //We have sent an auth request
      if( state.equals(STATES.AUTH.name()))
      {
         return facebookProcessor.handleAuthStage(request, response);
      }
      
      //Principal facebookPrincipal = null;
      if( state.equals(STATES.AUTHZ.name()))
      {  
         Principal principal = facebookProcessor.getPrincipal(request, response, context.getRealm());
         
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
   
   protected boolean processOpenID(Request request, Response response) throws IOException
   {
      Principal userPrincipal = request.getUserPrincipal();
      if(userPrincipal != null)
      {
         if(trace)
            log.trace("Logged in as:"+userPrincipal);
         return true;
      }

      if(!openidProcessor.isInitialized())
      {
         try
         {
            openidProcessor.initialize(roles);
         }
         catch (Exception e)
         { 
            throw new RuntimeException(e);
         }
      }

      HttpSession httpSession = request.getSession();
      String state = (String) httpSession.getAttribute("STATE");
      if(trace) log.trace("state="+ state);

      if( STATES.FINISH.name().equals(state))
         return true;

      if( state == null || state.isEmpty())
      { 
         return openidProcessor.prepareAndSendAuthRequest(request, response);
      } 
      //We have sent an auth request
      if( state.equals(STATES.AUTH.name()))
      {
         Session session = request.getSessionInternal(true);
         if (saveRestoreRequest)
         {
            this.saveRequest(request, session);
         }

         Principal principal = openidProcessor.processIncomingAuthResult(request, response, context.getRealm());
         String principalName = principal.getName();
         request.getSessionInternal().setNote(Constants.SESS_USERNAME_NOTE, principalName);
         request.getSessionInternal().setNote(Constants.SESS_PASSWORD_NOTE, "");
         request.setUserPrincipal(principal);

         if (saveRestoreRequest)
         {
            this.restoreRequest(request, request.getSessionInternal());
         }

         if(trace)
            log.trace("Logged in as:" + principal);
         register(request, response, principal, Constants.FORM_METHOD, principalName, "");
         return true;
      }
      return false;
   }
}