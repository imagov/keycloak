# Keycloak

* [pt-BR translation](https://github.com/imagov/keycloak/blob/master/README.pt-BR.md)

Keycloak gem was developed to integrate applications and services into [Red Hat](https://www.redhat.com)'s [Keycloak](http://www.keycloak.org/) system for user control, authentication, authorization, and session management.

Its development was based on version 3.2 of Keycloak, whose documentation can be found [here](http://www.keycloak.org/archive/documentation-3.2.html).

Publication of gem: https://rubygems.org/gems/keycloak

Exemple: https://github.com/imagov/example-gem-keycloak

## Installation

Add this line in your application's <b>gemfile</b>:

```ruby
gem 'keycloak'
```

Install the gem by running:

    $ bundle install

Or install it yourself:

    $ gem install keycloak
	
To add the configuration file:

	$ rails generate keycloak:config

	
## Use

Since you already have a Keycloak environment configured and the gem already installed, the next step is to define how the application will authenticate. Keycloak works with key authentication protocols, such as OpenID Connect, Oauth 2.0 and SAML 2.0, integrating system access through Single-Sign On, and can also provide access to <b>LDAP</b> or <b>Active Directory</b> users.

When you register a realm and also a Client in your Keycloak environment, you can download the Client installation file into the `config` folder of the application so that gem gets the information it needs to interact with Keycloak. To download this, simply access your Client's registry, click the <b>Installation</b> tab, select <b>Keycloak OIDC JSON</b> in the <b>Format option</b> field and click <b>Download</b>. If your application does not only work with a specific client (application server for APIs, for example), then you can tell what is the realm that gem will interact in the `keycloak.rb` configuration file.

Gem has a main module called <b>Keycloak</b>. Within this module there are three other modules: <b>Client</b>, <b>Admin</b> and <b>Internal</b>.

### Module Keycloak

The Keycloak module has some attributes and its definitions are fundamental for the perfect functioning of the gem in the application.

```ruby
Keycloak.installation_file = 'path/to/file.json'
```

Allows you to set the location of installation file if you have one. If not set, it will default to `keycloak.json` in the `config` folder of your repository. In any case, it will use installation file only if it's present.

```ruby
Keycloak.realm
```

If your application does not only work with a specific client (application server for APIs, for example), then you can tell the realm name that gem will interact in that attribute. When installed, gem creates the `keycloak.rb` file in `config / initializers`. This attribute can be found and defined in this file.


```ruby
Keycloak.auth_server_url
```

For the same scenario as the above attribute, you can tell the url of the realm that the gem will interact in that attribute. When installed, gem creates the `keycloak.rb` file in `config / initializers`. This attribute can be found and defined in this file.


```ruby
Keycloak.proxy
```

If the environment where your application will be used requires the use of proxy for the consumption of the Keycloak APIs, then define it in this attribute. When it is installed, gem creates the `keycloak.rb` file in `config/initializers`. This attribute can be found and defined in this file.


```ruby
Keycloak.generate_request_exception
```

This attribute is to define whether the HTTP exceptions generated in the returns of the requests made to Keycloak will or will not burst in the application. If set to `false`, then the exception will not be blown and the HTTP response will be returned to the application to do its own processing. The default value of this attribute is `true`. When it is installed, gem creates the `keycloak.rb` file in `config/initializers`. This attribute can be found and defined in this file.


```ruby
Keycloak.keycloak_controller
```

It is recommended that your application has a controller that centralizes the session actions that Keycloak will manage, such as login action, logout, session update, password reset, among others. Define in this attribute what is the name of the controller that will play this role. If your controller name is `SessionController`, then the value of this attribute should be `session` only. When it is installed, gem creates the `keycloak.rb` file in `config/initializers`. This attribute can be found and defined in this file.


```ruby
Keycloak.proc_cookie_token
```

This attribute is an anonymous method (lambda). The same must be implemented in the application so that the gem has access to the authentication token which, in turn, must be stored in the cookie. When performing the keycloak authentication through gem, the system must store the token returned in the browser cookie, such as:
```ruby
cookies.permanent[:keycloak_token] = Keycloak::Client.get_token(params[:user_login], params[:user_password])
```

The application can retrieve the token in the cookie by implementing the `Keycloak.proc_cookie_token` method as follows:
```ruby
Keycloak.proc_cookie_token = -> do
  cookies.permanent[:keycloak_token]
end
```
This way, every time gem needs to use the token information to consume a Keycloak service, it will invoke this lambda method.

```ruby
Keycloak.proc_external_attributes
```

Keycloak gives the possibility that new attributes are mapped to the user registry. However, when these attributes are application specific, it is recommended that you manage them yourself. To do this, the best solution is to create these attributes in the application - example: create a table in the database of the application itself containing the columns representing each of the attributes, also inserting in this table a unique key column, same as the User Id created in Keycloak, indicating that the one belonging to that Id has those attributes.
In order for gem to have access to these attributes, set the `Keycloak.proc_external_attributes` attribute to a lambda method by obtaining the attributes of the logged-in user. Example:
```ruby
Keycloak.proc_external_attributes = -> do
  attribute = UsuariosAtributo.find_or_create_by(user_keycloak_id: Keycloak::Client.get_attribute('sub'))
  if attribute.status.nil?
    attribute.status = false
    attribute.save
  end
  attribute
end
```


<b>Note:</b> The `Keycloak.proc_cookie_token` and `Keycloak.proc_external_attributes` attributes can be defined in the `initialize` of the controller `ApplicationController`.

```ruby
Keycloak.validate_token_when_call_has_role
```

The introspect of the token will be executed every time the `Keycloak::Client.has_role?` method is invoked, if this setting is set to `true`.


### Keycloak::Client

The `Keycloak::Client` module has the methods that represent the <b>endpoint</b> services. These services are fundamental for creating and updating tokens, logging in and logout, and also for obtaining the synthetic information of a logged in user. What enables gem to make use of all these services is the previously mentioned client installation file.

We will detail each of these methods:

```ruby
Keycloak::Client.get_token(user, password, client_id = '', secret = '')
```

If you choose to authenticate users using the screen of your own application, then use this method. Simply invoke it in the method of login in the `controller` defined with the session controller of your application, passing as parameter the <b>user</b> and the <b>password</b> informed by the user. If the authentication is valid, then a JSON containing the `access_token` and the `refresh_token` is returned.


```ruby
Keycloak::Client.url_login_redirect(redirect_uri, response_type = 'code')
```

To authenticate the users of your application using a template configured in Keycloak, redirect the request to the url returned in this method. Pass as a parameter the url that the user will have access in case of successful authentication (`redirect_uri`) and also the type of response (`response_type`), which if not informed, gem will assume the `code` value. If the authentication is successful, then a `code` will be returned that will enable you to request a token from <b>Keycloak</b>.


```ruby
Keycloak::Client.get_token_by_code(code, redirect_uri, client_id = '', secret = '')
```

When using the `Keycloak::Client.url_login_redirect` method to get a `code`, pass it as a parameter in this method so that Keycloak returns a token, thus logging the user in the application. The second parameter (`redirect_uri`) must be passed so that when a token is made available, Keycloak redirects to the url informed.


```ruby
Keycloak::Client.get_token_by_exchange(issuer, issuer_token, client_id = '', secret = '')
```

To get a token through a token previously obtained from a trusted provider (OpenID standard), such as Facebook, Gooble, Twitter, or even another realm configured in the keycloak, simply invoke this method, passing in the `issuer` parameter the provider alias configured in the realm, and in the `issuer_token` parameter the token obtained by that provider. This will return a token authenticated by your realm.


```ruby
Keycloak::Client.get_userinfo_issuer(access_token = '', userinfo_endpoint = '')
```

This method returns the user information of a provider (`issuer` of the `get_token_by_exchange` method represented by the `access_token` passed as parameter. If the `access_token` parameter is not informed, then the gem will get this information in the cookie.


```ruby
Keycloak::Client.get_token_by_refresh_token(refresh_token = '', client_id = '', secret = '')
```

When the user is already logged in and your application internally tracks the token expiration time provided by Keycloak, then this method can be used to renew that token if it is still valid. To do this, simply pass the `refresh_token` as a parameter. If you do not inform `refresh_token`, gem will use the `refresh_token` stored in the cookie.


```ruby
Keycloak::Client.get_token_introspection(token = '', client_id = '', secret = '', token_introspection_endpoint = '')
```

This method returns the information from the `token` session passed as parameter. Among the information returned, the most important is the `active` field, since it informs whether the token session passed in the parameter is active or not. This will help your application control whether the logged-in user session has expired or not. If no token is passed as a parameter, gem will use the last `access_token` stored in the application's cookie.


```ruby
Keycloak::Client.get_token_by_client_credentials(client_id = '', secret = '')
```

There are some Keycloak services like <b>password reset</b>, <b>user registration</b> in the initial screen of the application or even authentication following the standard <b>OAuth 2.0</b>, that the authentication of a user becomes unnecessary. Therefore, we can obtain a token using the credentials of its own application (Client) registered in Keycloak. To obtain this token, pass the `client_id` - informed by the person who registered your application in Keycloak - and the `secret` of your application generated by Keycloak - to generate a `secret`, the Access Type of your Client must be configured as `confidential`. If you do not pass any of these parameters, gem will use the credentials contained in the installation file mentioned above.


```ruby
Keycloak::Client.logout(redirect_uri = '', refresh_token = '', client_id = '', secret = '', end_session_endpoint = '')
```

When used before the expiration of the logged on user's session, this method terminates the session. If the `redirect_uri` parameter is fed, then Keycloak will redirect your application to the url informed after logout. The second parameter is `refresh_token`, obtained at the time of authentication or session update. If the latter is not informed, then the gem will use the `refresh_token` of the cookie


```ruby
Keycloak::Client.get_userinfo(access_token = '', userinfo_endpoint = '')
```

This method returns synthetic information from the user represented by the `access_token` passed as a parameter, such as `sub` - which is the authenticated user id -, `preferred_username` - which is the authenticated user name - and `email` - which is the user's email address. If the `access_token` parameter is not informed, then the gem will get this information in the cookie.


```ruby
Keycloak::Client.url_user_account
```

Returns the <b>url</b> for access to the realm user registry of the installation file (`keycloak.json`). To access the screen, Keycloak will require user authentication. After connected, and if has permission, the user will have access to his own personal information and could even change them.


```ruby
Keycloak::Client.has_role?(user_role, access_token = '', client_id = '', secret = '', token_introspection_endpoint = '')
```

The `has_role?` method decodes the JWT `access_token` and verifies that the user who owns the token has the <b>role</b> informed in the `user_role` parameter. If `access_token` is not informed then gem will use the `access_token` of the cookie.


```ruby
Keycloak::Client.user_signed_in?(access_token = '', client_id = '', secret = '', token_introspection_endpoint = '')
```

This method checks whether the `access_token` passed in the parameter is still active. To check whether the user is active or not, the gem invokes the `get_token_introspection` method internally. If `access_token` is not informed then gem will use the `access_token` of the cookie.


```ruby
Keycloak::Client.get_attribute(attribute_name, access_token = '')
```

This method decodes the JWT `access_token` and returns the value of the name attribute passed in the `attribute_name` parameter. This attribute can be a <b>mapper</b> - registered in the <b>Mappers</b> section of the Realm <b>Client</b> registry. If `access_token` is not informed then gem will use the `access_token` of the cookie.


```ruby
Keycloak::Client.token
```

Returns the last authenticated token stored in the cookie. When the `Keycloak.proc_cookie_token` method is implemented in the application and a user authenticates the application, this method returns the token of that user.


```ruby
Keycloak::Client.external_attributes
```

When the `Keycloak.proc_external_attributes` method is implemented, the `external_attributes` method returns it. The purpose of this method is to return the application-specific attributes not mapped in Keycloak.


### Keycloak::Admin

The `Keycloak :: Admin` module provides methods that represent the [REST APIs do Keycloak](http://www.keycloak.org/docs-api/3.2/rest-api/index.html). In order to use these APIs, an active `access_token` is required, that is, authentication must occur before using the methods for a valid token to be used as a credential. If `access_token` is not informed then gem will use the `access_token` of the cookie. The authenticated user must have the `role` of the respective service invoked - roles of the `realm-management` client, which represents the management of the realm.

The list of methods is shown below. The `{realm}` route parameter of all APIs will be obtained from the `keycloak.json` installation file:

```ruby
# GET /admin/realms/{realm}/users
Keycloak::Admin.get_users(query_parameters = nil, access_token = nil)
```

`get_users` returns a list of users, filtered according to the parameters <b>hash</b> passed in` query_parameters`.


```ruby
# POST /admin/realms/{realm}/users
Keycloak::Admin.create_user(user_representation, access_token = nil)
```

`create_user` creates a new user in Keycloak. The `user_representation` parameter must be a hash according to Keycloak [UserRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_userrepresentation). The return of this method will be `true` for success.


```ruby
# GET /admin/realms/{realm}/users/count
Keycloak::Admin.count_users(access_token = nil)
```
`count_users` returns the number of users in the realm.


```ruby
# GET /admin/realms/{realm}/users/{id}
Keycloak::Admin.get_user(id, access_token = nil)
```

`get_user` returns the user representation identified by the `id` parameter - which is the <b>ID</b> created by Keycloak when creating a new user.


```ruby
# PUT /admin/realms/{realm}/users/{id}
Keycloak::Admin.update_user(id, user_representation, access_token = nil)
```

`update_user` updates the user registry identified by `id` - which is the <b>ID</b> created by Keycloak when creating a new user. In the `user_representation` parameter should be a hash with the fields that will be changed, respecting the [UserRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_userrepresentation) of Keycloak. The return of this method will be `true` for success.


```ruby
# DELETE /admin/realms/{realm}/users/{id}
Keycloak::Admin.delete_user(id, access_token = nil)
```

`delete_user` excludes the user ID identified by the `id` - which is the <b>ID</b> created by Keycloak when creating a new user. The return of this method will be `true` for success.


```ruby
# DELETE /admin/realms/{realm}/users/{id}/consents/{client}
Keycloak::Admin.revoke_consent_user(id, client_id = nil, access_token = nil)
```

`revoke_consent_user` revokes the tokens of a user identified by `id` - which is the <b>ID</b> created by Keycloak when creating a new user - on the client identified by the `client_id` parameter.


```ruby
# PUT /admin/realms/{realm}/users/{id}/execute-actions-email
Keycloak::Admin.update_account_email(id, actions, redirect_uri = '', client_id = nil, access_token = nil)
```

`update_account_email` sends an account update email to the user represented by the `id` parameter. The email contains a link that the user can click to execute a set of actions represented by the `actions` parameter - which awaits an `array` of [actions defined by Keycloak](http://www.keycloak.org/docs/3.2/server_admin/topics/users/required-actions.html). An example value that can be passed to the `actions` parameter is `['UPDATE_PASSWORD']`, which indicates that the action that the user must take when clicking the link in the email is to change their password. In the `redirect_uri` parameter, if necessary, a url must be passed so that, at the end of sending the e-mail, the application is redirected. The `client_id` parameter should be informed if the Client responsible for the actions to be performed is not the same as the `keycloak.json` installation file.


```ruby
# GET /admin/realms/{realm}/users/{id}/role-mappings
Keycloak::Admin.get_role_mappings(id, access_token = nil)
```

`get_role_mappings` returns all <b>Role Mappings</b> in the realm assigned to the user identified by the `id` parameter, regardless of the Client.


```ruby
# GET /admin/realms/{realm}/groups
Keycloak::Admin.get_groups(query_parameters = nil, access_token = nil)
```

`get_groups` returns a list of [GroupRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_grouprepresentation) for the realm. The optional `query_parameters` parameter expects a hash with properties matching any of the [query parameters](https://www.keycloak.org/docs-api/3.2/rest-api/index.html#_groups_resource) accepted by the API.


```ruby
# GET /admin/realms/{realm}/clients
Keycloak::Admin.get_clients(query_parameters = nil, access_token = nil)
```

`get_clients` returns a list of [ClientRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_clientrepresentation) pertaining to the realm. The `query_parameters` parameter expects a hash with `clientId` attributes - if you want the list to be filtered by `client_id` - and `viewableOnly` - to filter whether the Keycloak Administration Clients will be returned in the list.


```ruby
# GET /admin/realms/{realm}/clients/{id}/roles
Keycloak::Admin.get_all_roles_client(id, access_token = nil)
```

`get_all_roles_client` returns a [RoleRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_rolerepresentation) list with all client <b>roles</b> identified by the `id` parameter - this parameter must be passed in the ID of the Clint and not `client_id`.


```ruby
# GET /admin/realms/{realm}/clients/{id}/roles/{role-name}
Keycloak::Admin.get_roles_client_by_name(id, role_name, access_token = nil)
```

`get_roles_client_by_name` returns the [RoleRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_rolerepresentation) of the role identified by the parameter `role_name` - which is the name of the role.


```ruby
# POST /admin/realms/{realm}/users/{id}/role-mappings/clients/{client}
Keycloak::Admin.add_client_level_roles_to_user(id, client, role_representation, access_token = nil)
```

`add_client_level_roles_to_user` inserts a <b>role</b> from the Client (represented by the `client` parameter) to the user represented by the `id` parameter. The `role_representation` parameter should receive an `array` of [RoleRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_rolerepresentation) that will be entered into the user. On success, the return will be `true`.


```ruby
# DELETE /admin/realms/{realm}/users/{id}/role-mappings/clients/{client}
Keycloak::Admin.delete_client_level_roles_from_user(id, client, role_representation, access_token = nil)
```

`delete_client_level_roles_from_user` deletes a <b>Client-Role</b> (representado pelo parâmetro `client`) of the user represented by the `id` parameter. The `role_representation` parameter should receive an `array` of [RoleRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_rolerepresentation) that will be removed on the user. On success, the return will be `true`.


```ruby
# GET /admin/realms/{realm}/users/{id}/role-mappings/clients/{client}
Keycloak::Admin.get_client_level_role_for_user_and_app(id, client, access_token = nil)
```

`get_client_level_role_for_user_and_app` return a list of [RoleRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_rolerepresentation) of client <b>Client-Roles</b>, represented by `client` parameter linked to the user represented by the `id` parameter.


```ruby
Keycloak::Admin.update_effective_user_roles(id, client_id, roles_names, access_token = nil)
```

`update_effective_user_roles` is not on the Keycloak <b>Admin APIs</b> list. This method binds to the user represented by the `id` parameter all the roles passed in an` array` in the `roles_names` parameter. The roles passed in the `roles_names` parameter must belong to the Client represented by the` client_id` parameter. If the user has the link with a role that is not in the `roles_names` parameter, this link will be removed because the purpose of this method is for the user to effectively assume the roles passed in this parameter. On success, the return will be `true`.


```ruby
PUT /admin/realms/{realm}/users/{id}/reset-password
Keycloak::Admin.reset_password(id, credential_representation, access_token = nil)
```

`reset_password` change the user password represented by `id` parameter. The new password is represented by `credential_representation` parameter, which is a set of information formatted under the [CredentialRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_credentialrepresentation) section of the Keycloak API manual.


```ruby
GET /admin/realms/{realm}/groups/{id}/role-mappings/clients/{client}/composite
Keycloak::Admin.get_effective_client_level_role_composite_user(id, client, access_token = nil)
```

`get_effective_client_level_role_composite_user` return a list (array) of [RoleRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_rolerepresentation) of a <b>Group</b> represented by `id` parameter attached to a <b>Client</b> represented by `client` parameter.


If there is any service in the manual [Keycloak Admin REST API](http://www.keycloak.org/docs-api/3.2/rest-api/index.html) that has not been implemented in this gem, there is a possibility of being invoked using the <b>Generics Methods</b> of the `Keycloak::Admin` model. The <b>Generics Methods</b> allow you to request any of the APIs, either `GET`,` POST`, `PUT` or` DELETE`, passing the request parameters as `hashes` in the parameters` query_parameters` and `body_parameter` of the <b>Generics Methods</b>.
<br>
The following are the <b>Generics Methods</b>:
<br>

```ruby
Keycloak::Admin.generic_get(service, query_parameters = nil, access_token = nil)
```

`generic_get` allows you to make <b>Keycloak</b> `GET` service requests. The part of the URI that identifies the service must be passed in the `service` parameter, already with the route parameters (such as `{client}`, for example) properly replaced. In the `query_parameters` parameter you can pass a `hash` containing the <b>Queries Parameters</b> of the request.<br>
Example:
```ruby
    Keycloak::Admin.generic_get("users/", {email: 'admin@test.com'}, "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldU...")
```


```ruby
Keycloak::Admin.generic_post(service, query_parameters, body_parameter, access_token = nil)
```

`generic_post` allows you to make <b>Keycloak</b> `POST` service requests. The part of the URI that identifies the service must be passed in the `service` parameter, already with the route parameters (such as `{client}`, for example) properly replaced. In the `query_parameters` parameter you can pass a `hash` containing the <b>Query Parameters</b> of the request. In the `body_parameter` parameter you can pass a `hash` containing the <b>Body Parameters</b> of the request.<br>
Example:
```ruby
    Keycloak::Admin.generic_post("users/", nil, { username: "admin", email: "admin@test.com", enabled: true }, "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldU...")
```

```ruby
Keycloak::Admin.generic_put(service, query_parameters, body_parameter, access_token = nil)
```

`generic_put` allows you to make <b>Keycloak</b> `PUT` service requests. The part of the URI that identifies the service must be passed in the `service` parameter, already with the route parameters (such as `{client}`, for example) properly replaced. In the `query_parameters` parameter you can pass a `hash` containing the <b>Query Parameters</b> of the request. In the `body_parameter` parameter you can pass a `hash` containing the <b>Body Parameters</b> of the request.


```ruby
Keycloak::Admin.generic_delete(service, query_parameters = nil, body_parameter = nil, access_token = nil)
```

`generic_delete` allows you to make <b>Keycloak</b> `DELETE` service requests. The part of the URI that identifies the service must be passed in the `service` parameter, already with the route parameters (such as `{client}`, for example) properly replaced. In the `query_parameters` parameter you can pass a `hash` containing the <b>Query Parameters</b> of the request. In the `body_parameter` parameter you can pass a `hash` containing the <b>Body Parameters</b> of the request.


### Keycloak::Internal

The `Keycloak::internal` module provides methods designed to facilitate interaction between the application and <b>Keycloak</b>. From the information found in the `keycloak.json` installation file, all invoked methods will be authenticated automatically, using the application credentials (`grant_type = client_credentials`), depending on the assigned roles assigned to it. request is authorized.


```ruby
Keycloak::Internal.get_users(query_parameters = nil, client_id = '', secret = '')
```

`get_users` invokes the `Keycloak::Admin.get_users` method that returns a list of users, filtered according to the parameters hash passed in `query_parameters`.


```ruby
Keycloak::Internal.get_groups(query_parameters = nil, client_id = '', secret = '')
```

`get_groups` invokes the `Keycloak::Admin.get_groups` method that returns the group hierarchy for the realm, filtered according to the parameters hash passed in `query_parameters`.


```ruby
Keycloak::Internal.change_password(user_id, redirect_uri = '', client_id = '', secret = '')
```

`change_password` will invoke the Keycloak `PUT /admin/realms/{realm}/users/{id}/execute-actions-email` API requesting the `UPDATE_PASSWORD` action. This will cause Keycloak to trigger an email to the user represented by the `user_id` parameter. The `redirect_uri` parameter is optional. If it is not filled, then there will be no link to click after the password reset action has been completed.


```ruby
Keycloak::Internal.get_user_info(user_login, whole_word = false, client_id = '', secret = ''))
```

`get_user_info`, based on the `user_login` parameter, which will be able to receive the `username` or the `email` of the user, will return an array of [UserRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_userrepresentation) in the case where the `whole_word` parameter is `false`, or it will return a [UserRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_userrepresentation) when the `whole_word` parameter is `true`. The `whole_word` parameter indicates whether the method should consider users that have `username` or `email` part of the expression passed in the `user_login` parameter - for the cases of `whole_word = false` - or that has exactly the last expression in this parameter - for the cases of `whole_word = true`.


```ruby
Keycloak::Internal.forgot_password(user_login, redirect_uri = '', client_id = '', secret = '')
```

`forgot_password` will invoke the `Keycloak::Internal.change_password` method after invoking the `Keycloak::Internal.get_user_info` method - passing in the `user_login` parameter of the described method the `user_login` parameter of this topic and passing `true` in the parameter `whole_word`. The use of this method is indicated for the cases of applications allow the reset of the password of the users without it is logged in.


```ruby
Keycloak::Internal.exists_name_or_email(value, user_id = '', client_id = '', secret = '')
```

`exists_name_or_email` checks whether a user with `username` or `email` already exists in the `value` parameter in the realm. The `user_id` parameter is used to pass the `ID` of a user in cases where it is desired to change the `username` or `email` of the same, so that they are considered in the `username` and `email verification` different users of the user with the `ID` informed in `user_id`.


```ruby
Keycloak::Internal.get_logged_user_info(client_id = '', secret = '')
```

`get_logged_user_info` returns the [UserRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_userrepresentation) of the user logged into the application.


```ruby
# GET /admin/realms/{realm}/users
Keycloak::Internal.logged_federation_user?(client_id = '', secret = '')
```

`logged_federation_user?` method invokes the `Keycloak::Internal.get_logged_user_info` method and checks to see if it is an <b>Federation User</b> (an LDAP user for example).


```ruby
# GET /admin/realms/{realm}/users
Keycloak::Internal.create_starter_user(username, password, email, client_roles_names, proc = nil, client_id = '', secret = '')
```

`create_starter_user` is suitable for applications that allow the creation of new users without a user being logged in or even to create new users from `rake db: seed`. In the `username`, `password` and `email` parameters, the user name, password, and email, respectively, must be passed. In the `client_roles_names` parameter, a list (array) with the name of the `roles` of the Client that will be assigned to the user must be passed. The `proc` parameter is a <b>lambda</b> method that will make available the [UserRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_userrepresentation) of the created user as a parameter, so that actions should be defined by the application. This method returns the same return of the `proc` parameter method if it is set, otherwise it will return to [UserRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_userrepresentation) of the created user.


```ruby
Keycloak::Internal.get_client_roles(client_id = '', secret = '')
```

`get_client_roles` will return an array of [RoleRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_rolerepresentation) from the Client indicated in the `client_id` parameter or, in the absence of this, by the client of the `keycloak.json` installation file.


```ruby
Keycloak::Internal.get_client_user_roles(user_id, client_id = '', secret = '')
```

`get_client_user_roles` will invoke the `Keycloak::Admin.get_effective_client_level_role_composite_user` method by considering the Client indicated in the `client_id` parameter or, if not, by the client of the `keycloak.json` installation file and the user represented by the `user_id` parameter.


```ruby
Keycloak::Internal.has_role?(user_id, user_role, client_id = '', secret = '')
```

`has_role?` informing the user represented by the `user_id` parameter has <b>role</b> with the name represented by the `user_role` parameter.
