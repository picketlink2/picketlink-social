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
package org.picketlink.social.openid.auth;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

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
import org.picketlink.identity.federation.core.util.StringUtil;

/**
 * Tomcat Authenticator that provides OpenID based authentication
 * @author Anil Saldhana
 * @since Sep 17, 2011
 */
public class OpenIDConsumerAuthenticator extends FormAuthenticator
{
   protected static Logger log = Logger.getLogger(OpenIDConsumerAuthenticator.class);
   protected boolean trace = log.isTraceEnabled(); 

   private enum STATES { AUTH, AUTHZ, FINISH};

   public static ThreadLocal<Principal> cachedPrincipal = new ThreadLocal<Principal>();

   public static ThreadLocal<List<String>> cachedRoles = new ThreadLocal<List<String>>();
   public static String EMPTY_PASSWORD = "EMPTY";

   private String returnURL = null;

   private String requiredAttributes = "name,email,ax_firstName,ax_lastName,ax_fullName";

   private String optionalAttributes = null;

   protected List<String> roles = new ArrayList<String>();

   //Whether the authenticator has to to save and restore request
   protected boolean saveRestoreRequest = true;

   protected OpenIDProcessor processor = null;

   public void setReturnURL(String returnURL)
   {
      this.returnURL = returnURL;
   }

   public void setRequiredAttributes(String requiredAttributes)
   {
      this.requiredAttributes = requiredAttributes;
   }

   public void setOptionalAttributes(String optionalAttributes)
   {
      this.optionalAttributes = optionalAttributes;
   }

   public void setSaveRestoreRequest(boolean saveRestoreRequest)
   {
      this.saveRestoreRequest = saveRestoreRequest;
   } 

   /**
    * A comma separated string that represents the roles the web app
    * needs to pass authorization
    * @param roleStr
    */
   public void setRoleString(String roleStr)
   {
      if(roleStr == null)
         throw new RuntimeException("Role String is null in configuration");
      List<String> tokens = StringUtil.tokenize(roleStr);
      for(String token: tokens)
      {
         roles.add(token);
      }
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
      if(processor == null)
         processor = new OpenIDProcessor(returnURL, requiredAttributes, optionalAttributes);

      Principal userPrincipal = request.getUserPrincipal();
      if(userPrincipal != null)
      {
         if(trace)
            log.trace("Logged in as:"+userPrincipal);
         return true;
      }

      if(!processor.isInitialized())
      {
         try
         {
            processor.initialize(roles);
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
         return processor.prepareAndSendAuthRequest(request, response);
      } 
      //We have sent an auth request
      if( state.equals(STATES.AUTH.name()))
      {
         Session session = request.getSessionInternal(true);
         if (saveRestoreRequest)
         {
            this.saveRequest(request, session);
         }

         Principal principal = processor.processIncomingAuthResult(request, response, context.getRealm());
         if(principal == null)
            throw new RuntimeException("Principal was null. Maybe login modules need to be configured properly.");
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