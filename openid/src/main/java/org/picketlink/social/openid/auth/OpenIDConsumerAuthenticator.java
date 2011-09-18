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
import java.net.URL;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.log4j.Logger;
import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.MessageException;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;
import org.picketlink.identity.federation.core.util.StringUtil;
import org.picketlink.social.openid.OpenIdPrincipal;
import org.picketlink.social.openid.constants.OpenIDAliasMapper;

/**
 * Tomcat Authenticator that provides OpenID based authentication
 * @author Anil Saldhana
 * @since Sep 17, 2011
 */
public class OpenIDConsumerAuthenticator extends FormAuthenticator
{
   protected static Logger log = Logger.getLogger(OpenIDConsumerAuthenticator.class);
   protected boolean trace = log.isTraceEnabled();
   
   private enum Providers
   {
      GOOGLE("https://www.google.com/accounts/o8/id"),
      YAHOO("https://me.yahoo.com/"),
      MYSPACE("myspace.com"),
      MYOPENID("https://myopenid.com/");
      
      private String name;

      Providers(String name)
      {
         this.name = name;
      }
      String get()
      {
         return name;
      }
   }
   private enum STATES { AUTH, AUTHZ, FINISH};
   
   public static ThreadLocal<Principal> cachedPrincipal = new ThreadLocal<Principal>();
   
   public static ThreadLocal<List<String>> cachedRoles = new ThreadLocal<List<String>>();
   public static String EMPTY_PASSWORD = "EMPTY";
   
   private ConsumerManager openIdConsumerManager = null;
   
   private String openIdServiceUrl = null;
   
   private String returnURL = null;
   
   private String requiredAttributes = "name,email,ax_firstName,ax_lastName,ax_fullName";
   
   private String optionalAttributes = null;
   
   private FetchRequest fetchRequest;
   protected List<String> roles = new ArrayList<String>();
   
   //Whether the authenticator has to to save and restore request
   protected boolean saveRestoreRequest = true;
   
   protected boolean initialized = false;
   
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

   public void initialize() throws MessageException, ConsumerException
   {
      if(openIdConsumerManager == null)
         openIdConsumerManager = new ConsumerManager();
      
      fetchRequest = FetchRequest.createFetchRequest();
      //Work on the required attributes
      if(StringUtil.isNotNull(requiredAttributes))
      {
         List<String> tokens = StringUtil.tokenize(requiredAttributes);
         for(String token: tokens)
         {
            fetchRequest.addAttribute(token, OpenIDAliasMapper.get(token),true);
         }
      }
      //Work on the optional attributes
      if(StringUtil.isNotNull(optionalAttributes))
      {
         List<String> tokens = StringUtil.tokenize(optionalAttributes);
         for(String token: tokens)
         {
            String type = OpenIDAliasMapper.get(token);
            if(type == null)
            {
               log.error("Null Type returned for " + token);
            }
            fetchRequest.addAttribute(token, type,false);
         }
      }
      initialized = true;
   }

   public boolean authenticate(Request request, Response response, LoginConfig loginConfig) throws IOException
   {  
      Principal userPrincipal = request.getUserPrincipal();
      if(userPrincipal != null)
      {
         if(trace)
            log.trace("Logged in as:"+userPrincipal);
         return true;
      }
      
      if(!initialized)
      {
         try
         {
            initialize();
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
         return processSend(request, response, loginConfig);
      } 
      //We have sent an auth request
      if( state.equals(STATES.AUTH.name()))
      {
         return processIncomingResult(request, response, loginConfig);
      }
      return false;
   } 
   
   @SuppressWarnings("unchecked")
   protected boolean processSend(Request request, Response response, LoginConfig loginConfig) throws IOException
   { 
      //Figure out the service url
      String service = request.getParameter("service");
      determineServiceUrl(service);
      
      String openId = openIdServiceUrl;
      Session session = request.getSessionInternal(true);
      if(openId != null)
      {
         if (saveRestoreRequest)
         {
            this.saveRequest(request, session);
         }
         session.setNote("openid", openId);
         List<DiscoveryInformation> discoveries;
         try
         {
            discoveries = openIdConsumerManager.discover(openId);
         }
         catch (DiscoveryException e)
         { 
            throw new RuntimeException(e);
         }

         DiscoveryInformation discovered = openIdConsumerManager.associate(discoveries);
         session.setNote("discovery", discovered);
         try
         {
            AuthRequest authReq = openIdConsumerManager.authenticate(discovered, returnURL);

            //Add in required attributes
            authReq.addExtension(fetchRequest);
            
            String url = authReq.getDestinationUrl(true);
            response.sendRedirect(url);
            
            request.getSession().setAttribute("STATE", STATES.AUTH.name());
            return false;
         }
         catch (Exception e)
         { 
            throw new RuntimeException(e);
         }
      } 
      return false;
   }
   
   @SuppressWarnings("unchecked")
   protected boolean processIncomingResult(Request request, Response response, LoginConfig loginConfig) throws IOException
   {
      Session session = request.getSessionInternal(false);
      if(session == null)
         throw new RuntimeException("wrong lifecycle: session was null");
      
      // extract the parameters from the authentication response
      // (which comes in as a HTTP request from the OpenID provider)
      ParameterList responseParamList = new ParameterList(request.getParameterMap());
      // retrieve the previously stored discovery information
      DiscoveryInformation discovered = (DiscoveryInformation) session.getNote("discovery");
      if(discovered == null)
         throw new RuntimeException("discovered information was null");
      // extract the receiving URL from the HTTP request
      StringBuffer receivingURL = request.getRequestURL();
      String queryString = request.getQueryString();
      if (queryString != null && queryString.length() > 0)
         receivingURL.append("?").append(request.getQueryString());

      // verify the response; ConsumerManager needs to be the same
      // (static) instance used to place the authentication request
      VerificationResult verification;
      try
      {
         verification = openIdConsumerManager.verify(receivingURL.toString(), responseParamList, discovered);
      }
      catch (Exception e)
      { 
         throw new RuntimeException(e);
      }

      // examine the verification result and extract the verified identifier
      Identifier identifier = verification.getVerifiedId();

      if (identifier != null)
      {
         AuthSuccess authSuccess = (AuthSuccess) verification.getAuthResponse();

         Map<String, List<String>> attributes = null;
         if (authSuccess.hasExtension(AxMessage.OPENID_NS_AX))
         {
            FetchResponse fetchResp;
            try
            {
               fetchResp = (FetchResponse) authSuccess.getExtension(AxMessage.OPENID_NS_AX);
            }
            catch (MessageException e)
            {
               throw new RuntimeException(e);
            }

            attributes = fetchResp.getAttributes();
         }

         Principal principal = null;
         OpenIdPrincipal openIDPrincipal = createPrincipal(identifier.getIdentifier(), discovered.getOPEndpoint(),
               attributes);
         request.getSession().setAttribute("PRINCIPAL", openIDPrincipal);
         
         String principalName = openIDPrincipal.getName();
         cachedPrincipal.set(openIDPrincipal);
         
         if(isJBossEnv())
         {
            cachedRoles.set(roles);
            principal = context.getRealm().authenticate(principalName, EMPTY_PASSWORD); 
         }
         else
         { 
            //Create a Tomcat Generic Principal
            principal = new GenericPrincipal(getContainer().getRealm(), principalName, null, roles, openIDPrincipal);
         }
         
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
   

   public boolean authenticate(HttpServletRequest request, HttpServletResponse response, LoginConfig loginConfig) throws IOException
   {
      if(request instanceof Request == false)
         throw new IOException("Not of type Catalina request");
      if(response instanceof Response == false)
         throw new IOException("Not of type Catalina response");
      return authenticate((Request)request, (Response)response, loginConfig);
   }

   private OpenIdPrincipal createPrincipal(String identifier, URL openIdProvider, Map<String, List<String>> attributes)
   {
      return new OpenIdPrincipal(identifier, openIdProvider, attributes);
   }
   
   private boolean isJBossEnv()
   {
      ClassLoader tcl = SecurityActions.getContextClassLoader();
      Class<?> clazz = null;
      try
      {
         clazz = tcl.loadClass("org.jboss.system.Service");
      }
      catch (ClassNotFoundException e)
      { 
      }
      if( clazz != null )
         return true;
      return false;
   }
   
   private void determineServiceUrl(String service)
   {
      openIdServiceUrl = Providers.GOOGLE.get();
      if(StringUtil.isNotNull(service))
      {
         if("google".equals(service))
            openIdServiceUrl = Providers.GOOGLE.get();
         else if("yahoo".equals(service))
            openIdServiceUrl = Providers.YAHOO.get();
         else if("myspace".equals(service))
            openIdServiceUrl = Providers.MYSPACE.get();
         else if("myopenid".equals(service))
            openIdServiceUrl = Providers.MYOPENID.get();
      }
   }
}