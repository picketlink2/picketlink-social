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
package org.picketlink.social.reg;

import java.io.IOException;
import java.security.Principal;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.picketlink.social.facebook.FacebookPrincipal;
import org.picketlink.social.openid.OpenIdPrincipal;

/**
 * A Valve that can be added after the authenticator to look into the authenticated principal and derive useful information to
 * register the user
 *
 * @author Anil Saldhana
 * @since Sep 22, 2011
 */
public class RegistrationValve extends ValveBase {
    public void invoke(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        if (request instanceof Request == false)
            throw new IOException("Not of type Catalina request");
        if (response instanceof Response == false)
            throw new IOException("Not of type Catalina response");
        invoke((Request) request, (Response) response);
    }

    public void invoke(Request request, Response response) throws IOException, ServletException {
        HttpSession session = request.getSession();
        Principal principal = (Principal) session.getAttribute("PRINCIPAL");
        if (principal != null) {
            UserRegistration user = null;
            if (principal instanceof OpenIdPrincipal) {
                user = processOpenIDPrincipal((OpenIdPrincipal) principal);
            } else if (principal instanceof FacebookPrincipal) {
                user = processFacebookPrincipal((FacebookPrincipal) principal);
            } else
                throw new ServletException("Unknown principal type:" + principal);
            if (user != null) {
                session.setAttribute("user", user);
            }
        }
        getNext().invoke(request, response);
    }

    private UserRegistration processOpenIDPrincipal(OpenIdPrincipal openIDPrincipal) {
        UserRegistration user = new UserRegistration();
        Map<String, List<String>> attributes = openIDPrincipal.getAttributes();
        user.setIdentifier(openIDPrincipal.getIdentifier());

        if (attributes != null) {
            List<String> values = attributes.get("ax_firstName");
            if (values != null && values.size() > 0)
                user.setFirstName(values.get(0));

            // Try the last name
            values = attributes.get("ax_lastName");
            if (values != null && values.size() > 0)
                user.setLastName(values.get(0));

            // Try the full name
            values = attributes.get("ax_fullName");
            if (values != null && values.size() > 0)
                user.setFullName(values.get(0));

            values = attributes.get("fullname"); // Yahoo
            if (values != null && values.size() > 0)
                user.setFullName(values.get(0));

            // Email
            values = attributes.get("ax_email");
            if (values != null && values.size() > 0)
                user.setEmail(values.get(0));
        }
        return user;
    }

    private UserRegistration processFacebookPrincipal(FacebookPrincipal facebookPrincipal) {
        UserRegistration user = new UserRegistration();
        user.setEmail(facebookPrincipal.getEmail());
        user.setFirstName(facebookPrincipal.getFirstName());
        user.setLastName(facebookPrincipal.getLastName());
        user.setIdentifier(facebookPrincipal.getId());
        return user;
    }
}