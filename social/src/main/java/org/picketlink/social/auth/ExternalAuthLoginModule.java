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

import java.security.Principal;
import java.security.acl.Group;
import java.util.List;

import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;
import org.picketlink.social.facebook.FacebookProcessor;
import org.picketlink.social.openid.auth.OpenIDProcessor;

/**
 * A {@link LoginModule} for JBoss environment to support external 3rd party authentication
 * @author Anil Saldhana
 * @since Sep 22, 2011
 */
public class ExternalAuthLoginModule extends UsernamePasswordLoginModule
{
   @Override
   protected Principal getIdentity()
   {
      Principal principal = null;
      //Try facebook
      principal = FacebookProcessor.cachedPrincipal.get();
      if(principal == null )
         principal =  OpenIDProcessor.cachedPrincipal.get();
      return principal;
   }

   @Override
   protected String getUsersPassword() throws LoginException
   {
      return OpenIDProcessor.EMPTY_PASSWORD;
   }

   @Override
   protected Group[] getRoleSets() throws LoginException
   {   
      Group group = new SimpleGroup("Roles"); 

      List<String> roles = OpenIDProcessor.cachedRoles.get();

      if(roles != null)
      {
         for(String role: roles)
         {
            group.addMember(new SimplePrincipal(role));
         }
      }
      roles = FacebookProcessor.cachedRoles.get();
      if(roles != null)
      {
         for(String role: roles)
         {
            Principal rolePrincipal = new SimplePrincipal(role);
            if(group.isMember(rolePrincipal) == false)
            {
               group.addMember(rolePrincipal); 
            }
         }
      }
      return new Group[] {group};
   }
}