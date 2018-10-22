/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2018 ForgeRock AS.
 */
package com.xign.forgerock;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.shared.debug.Debug;

import com.xign.forgerock.exception.XignTokenException;
import com.xign.forgerock.util.JWTClaims;
import com.xign.forgerock.util.UserInfoSelector;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;

import javax.inject.Inject;

import javax.security.auth.callback.NameCallback;
import org.forgerock.json.JsonValue;
import static org.forgerock.openam.auth.node.api.Action.send;
import javax.security.auth.callback.Callback;

/**
 * A node that checks to see if zero-page login headers have specified username
 * and shared key for this request.
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = XignPush.Config.class)
//TODO combine into one node with one config
public class XignPush extends AbstractDecisionNode {

    private final Config config;
    private final CoreWrapper coreWrapper;
    private final static String DEBUG_FILE = "XignPush";
    private Debug debug = Debug.getInstance(DEBUG_FILE);

    /**
     * Configuration for the node.
     */
    public interface Config {

        //TODO Remove filestore config, add as configuration option in node so we don't need to do file I/O for every
        // process call
        //TODO Add property name in xignAuthNode for localization
        @Attribute(order = 100)
        String pathToXignConfig();

        //TODO Add property name in xignAuthNode for localization
        @Attribute(order = 200)
        Map<String, String> mapping();
    }

    /**
     * Create the node.
     *
     * @param config The service config.
     */
    @Inject
    public XignPush(@Assisted Config config, CoreWrapper coreWrapper) {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

    private String findCallbackValue(TreeContext context) {
        for (Callback callback : context.getAllCallbacks()) {
            NameCallback ncb = (NameCallback) callback;
            if ("username".equals(ncb.getPrompt())) {
                return ncb.getName();
            }
        }
        return "";
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        if (context.hasCallbacks()) {

            String inputUsername = findCallbackValue(context);

            InputStream fin;
            try {
                fin = new FileInputStream(config.pathToXignConfig());
            } catch (FileNotFoundException ex) {
                debug.error(ex.getMessage());
                throw new NodeProcessException(ex.getMessage());
            }

            String username;
            try {
                // select which attributes should delivered in response
                UserInfoSelector selector = new UserInfoSelector();
                selector.setNickname(1);
                selector.setEmail(1);

                // request push login for username and retrieve token
                PushFetcherClient pushClient = new PushFetcherClient(fin, null);
                JWTClaims claims = pushClient.requestPushWithUsername(inputUsername, selector);
                username = claims.getNickname();
            } catch (XignTokenException ex) {
                debug.error(ex.getMessage());
                throw new NodeProcessException(ex.getMessage());
            }

            // get mapping of name = xign-id -> openam-id
            String mappingName = config.mapping().get(username);

            debug.message("mapping username '" + username + "' to AM Identity '" + mappingName + "'");

            if (mappingName == null) {
                debug.error("no mapping for username " + username);
                throw new NodeProcessException("no mapping for username " + username);
            }

            return makeDecision(mappingName, context);

        } else {
            List<Callback> callbacks = new ArrayList<>(1);
            NameCallback nameCallback = new NameCallback("username");
            callbacks.add(nameCallback);
            return send(ImmutableList.copyOf(callbacks)).build();

        }
    }

    private Action makeDecision(String mappingName, TreeContext context) {
        //check if identity exists with username
        AMIdentity id;
        try {
            id = coreWrapper.getIdentity(mappingName, "/");
        } catch (Exception e) {
            System.err.println(e.getMessage());
            return goTo(false).build();
        }

        if (id != null) { // exists, login user
            debug.message("logging in user '" + id.getName() + "'");
            JsonValue newSharedState = context.sharedState.copy();
            newSharedState.put("username", mappingName);
            return goTo(true).replaceSharedState(newSharedState).build();
        } else {
            debug.error("user not known");
            return goTo(false).build();
        }
    }
}
