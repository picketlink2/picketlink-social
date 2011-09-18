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

import java.security.Principal;
import java.security.acl.Group;
import java.util.List;

import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;

/**
 * A {@link LoginModule} for JBoss environment
 * @author Anil Saldhana
 * @since May 19, 2011
 */
public class FacebookLoginModule extends UsernamePasswordLoginModule
{ 
   @Override
   protected Principal getIdentity()
   {
      return FacebookAuthenticator.cachedPrincipal.get();
   }

   @Override
   protected String getUsersPassword() throws LoginException
   {
      return FacebookAuthenticator.EMPTY_PASSWORD;
   }

   @Override
   protected Group[] getRoleSets() throws LoginException
   {   
      Group group = new SimpleGroup("Roles"); 

      List<String> roles = FacebookAuthenticator.cachedRoles.get();

      if(roles != null)
      {
         for(String role: roles)
         {
            group.addMember(new SimplePrincipal(role));
         }
      }
      return new Group[] {group};
   }
}