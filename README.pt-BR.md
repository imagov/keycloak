# Keycloak
A gem Keycloak foi desenvolvida para integrar aplicações e serviços ao sistema [Keycloak](http://www.keycloak.org/) da [Red Hat](https://www.redhat.com) para controle de usuários, autenticação, autorização e sessão.

O seu desenvolvimento foi baseado na versão 3.2 do Keycloak, cuja documentação pode ser encontrada [aqui](http://www.keycloak.org/archive/documentation-3.2.html).

Publicação da gem: https://rubygems.org/gems/keycloak

Exemplo: https://github.com/imagov/example-gem-keycloak

## Instalação

Adicione esta linha no <b>Gemfile</b> de sua aplicação:

```ruby
gem 'keycloak'
```

Então execute:

    $ bundle

Ou instale você mesmo:

    $ gem install keycloak

Para adicionar o arquivo de configuração:

    $ rails generate keycloak:config

## Utilização

Considerando que você já possua um ambiente do Keycloak configurado e a gem já instalada, o próximo passo é definir como será a autenticação da aplicação. O Keycloak trabalha com os principais protocolos de autenticação, tais como o OpenID Connect, Oauth 2.0 e SAML 2.0, integrando acesso a sistemas via Single-Sign On, podendo inclusive disponibilizar acessos a usuários LDAP ou Active Directory.

Ao cadastrar um Reino e também um Client no seu ambiente Keycloak, você poderá fazer o download do arquivo de instalação do Client para dentro da pasta `config` da aplicação, para que a gem obtenha as informações necessárias para interagir com o Keycloak. Para fazer esse download, basta acessar o cadastro de seu Client, clicar na aba <b>Installation</b>, selecionar <b>Keycloak OIDC JSON</b> no campo <b>Format option</b> e clicar em <b>Download</b>. Caso a sua aplicação não trabalhe apenas com um client específico (aplicação servidora de APIs, por exemplo), então você poderá informar o reino que a gem irá interagir no arquivo de configuração `keycloak.rb`.

A gem possui um módulo principal chamado <b>Keycloak</b>. Dentro desse módulo há três outros módulos: <b>Client</b>, <b>Admin</b> e <b>Internal</b>.

### Module Keycloak

O módulo Keycloak possui alguns atributos e suas definições são fundamentais para o perfeito funcionamento da gem na aplicação.

```ruby
Keycloak.installation_file = 'path/to/file.json'
```

Permite você determinar o local do arquivo de instalação do Keycloak, caso você esteja utilizando um. Se não for informado, o caminho default será `config/Keycloak.json`.

```ruby
Keycloak.realm
```

Se a sua aplicação não trabalha apenas com um client específico (aplicação servidora de APIs, por exemplo), então você poderá informar o nome do reino que a gem irá interagir nesse atributo. Ao ser instalada, a gem cria o arquivo `keycloak.rb` em `config/initializers`. Este atributo pode ser encontrado e definido nesse arquivo.


```ruby
Keycloak.auth_server_url
```

Para o mesmo cenário do atributo acima, você poderá informar a url do reino que a gem irá interagir nesse atributo. Ao ser instalada, a gem cria o arquivo `keycloak.rb` em `config/initializers`. Este atributo pode ser encontrado e definido nesse arquivo.


```ruby
Keycloak.proxy
```

Caso o ambiente onde a sua aplicação será utilizada exija a utilização de proxy para o consumo das APIs do Keycloak, então defina-o neste atributo. Ao ser instalada, a gem cria o arquivo `keycloak.rb` em `config/initializers`. Este atributo pode ser encontrado e definido nesse arquivo.

```ruby
Keycloak.generate_request_exception
```

Este atributo serve para definir se as exceções HTTP geradas nos retornos das requisições feitas para o Keycloak serão ou não estouradas na aplicação. Caso definido como `false`, então a exceção não será estourada e a resposta HTTP será retornada para a aplicação fazer o seu próprio tratamento. O valor default deste atributo é `true`. Ao ser instalada, a gem cria o arquivo `keycloak.rb` em `config/initializers`. Este atributo pode ser encontrado e definido nesse arquivo.


```ruby
Keycloak.keycloak_controller
```

É recomendado que a sua aplicação possua um controller que centraliza as ações de sessão que o Keycloak irá gerenciar, tais como a ação de login, logout, atualização de sessão, reset de senha, entre outras. Defina neste atributo qual é o nome do controller que desempenhará esse papel. Se o nome do seu controller é `SessionController`, então o valor deste atributo deverá ser apenas `session`. Ao ser instalada, a gem cria o arquivo `keycloak.rb` em `config/initializers`. Este atributo pode ser encontrado e definido nesse arquivo.


```ruby
Keycloak.proc_cookie_token
```

Este atributo trata-se de um método anônimo (lambda). O mesmo deve ser implementado na aplicação para que a gem tenha acesso ao token de autenticação que, por sua vez, deverá ser armazenado no cookie. Ao realizar a autenticação no keycloak através da gem, o sistema deverá armazenar o token retornado no cookie do browser, como por exemplo: 
```ruby
cookies.permanent[:keycloak_token] = Keycloak::Client.get_token(params[:user_login], params[:user_password])
```
A aplicação poderá recuperar o token no cookie implementando o método `Keycloak.proc_cookie_token` da seguinte forma:
```ruby
Keycloak.proc_cookie_token = -> do
  cookies.permanent[:keycloak_token]
end
```
Desta forma, todas as vezes que a gem precisar utilizar as informações do token para consumir um serviço do Keycloak, ele irá invocar este método lambda.


```ruby
Keycloak.proc_external_attributes
```

O Keycloak dá a possibilidade de que novos atributos sejam mapeados no cadastro de usuários. Porém, quando esses atributos são específicos da aplicação, recomenda-se que a própria os gerencie. Para isso, a melhor solução é criar esses atributos na aplicação - exemplo: criar uma tabela no banco de dados da própria aplicação contendo as colunas representando cada um dos atributos, inserindo também nessa tabela uma coluna de identificação única (unique key), contendo na mesma o Id do usuário criado no Keycloak, indicando que esse pertencente àquele Id possui aqueles atributos.
Para que a gem tenha acesso a esses atributos, defina o atributo`Keycloak.proc_external_attributes` com um método lambda obtendo do `model` os atributos do usuário logado. Exemplo:
```ruby
Keycloak.proc_external_attributes = -> do
  atributos = UsuariosAtributo.find_or_create_by(user_keycloak_id: Keycloak::Client.get_attribute('sub'))
  if atributos.status.nil?
    atributos.status = false
    atributos.save
  end
  atributos
end
```

<b>Observação:</b> Os atributos `Keycloak.proc_cookie_token` e `Keycloak.proc_external_attributes` podem ser definidos no `initialize` do controller `ApplicationController`.


```ruby
Keycloak.validate_token_when_call_has_role
```

Será executado o introspect do token todas as vezes que o método `Keycloak::Client.has_role?` for invocado, caso esta configuração esteja setada como `true`.


### Keycloak::Client

O módulo `Keycloak::Client` possui os métodos que representam os serviços de <b>endpoints</b>. Esses serviços são fundamentais para a criação e atualização de tokens, efetuação de login e logout, e, também para a obtenção de informações sintéticas de um usuário logado. O que habilita a gem a fazer uso de todos esses serviços é o arquivo de instalação do client citado anteriormente.

Vamos ao detalhamento de cada um desses métodos:


```ruby
Keycloak::Client.get_token(user, password, client_id = '', secret = '')
```

Caso você opte por efetuar a autenticação dos usuários utilizando a tela da sua própria aplicação, então utilize esse método. Basta invocá-lo no método de login no `controller` definido com o controlador de sessão de sua aplicação, passando como parâmetro o <b>usuário</b> e a <b>senha</b> informados pelo usuário. Caso a autenticação seja válida, então será retornado um JSON contendo entre as informações principais o `access_token` e o `refresh_token`.


```ruby
Keycloak::Client.url_login_redirect(redirect_uri, response_type = 'code')
```

Para efetuar a autenticação dos usuários de sua aplicação utilizando um template configurado no Keycloak, redirecione a requisição para a url retornada nesse método. Passe como parâmetro a url que o usuário terá acesso no caso de êxito na autenticação(`redirect_uri`) e também o tipo de resposta (`response_type`), que caso não informado, a gem assumirá o valor `code`. Caso a autenticação seja bem sucedida, então será retornado um `code` que te habilitará a requisitar um token ao Keycloak.


```ruby
Keycloak::Client.get_token_by_code(code, redirect_uri, client_id = '', secret = '')
```

Ao utilizar o método `Keycloak::Client.url_login_redirect` para obter um `code`, passe-o como parâmetro neste método para que o Keycloak retorne um token, efetuando assim o login do usuário na aplicação. O segundo parâmetro (`redirect_uri`) deve ser passado para que, ao disponibilizar um token, o Keycloak redirecione para a url informada.


```ruby
Keycloak::Client.get_token_by_exchange(issuer, issuer_token, client_id = '', secret = '')
```

Para obter um token através de um token obtido anteriormente de um provedor confiável (padrão OpenID), como Facebook, Gooble, Twitter, ou até mesmo outro reino configurado no keycloak, basta invocar este método, passando no parâmetro `issuer` o alias do provedor configurado no reino, e, no parâmetro `issuer_token` o token obtido por esse provedor. Com isso, será retornado um token autenticado pelo teu reino.


```ruby
Keycloak::Client.get_userinfo_issuer(access_token = '', userinfo_endpoint = '')
```

Esse método retorna as informações do usuário de um provevedor (`issuer` do método `get_token_by_exchange`) representado pelo `access_token` passado como parâmetro. Caso o parâmetro `access_token` não seja informado, então a gem obterá essa informação no cookie.


```ruby
Keycloak::Client.get_token_by_refresh_token(refresh_token = '', client_id = '', secret = '')
```

Quando o usuário já estiver logado e a sua aplicação acompanhar internamente o tempo de expiração do token fornecido pelo Keycloak, então esse método poderá ser utilizado para a renovação desse token, caso o mesmo ainda seja válido. Para isso, basta passar como parãmetro o `refresh_token`. Caso não seja informado o `refresh_token`, a gem utilizará o `refresh_token` armazenado no cookie.


```ruby
Keycloak::Client.get_token_introspection(token = '', client_id = '', secret = '', token_introspection_endpoint = '')
```

Esse método retorna a as informações da sessão do `token` passado como parâmetro. Entre as informações retornadas, a mais importante é o campo `active`, pois ele informa se a sessão do token passado no parâmetro é ativo ou não. Isso auxiliará a sua aplicação a controlar se a sessão do usuário logado expirou ou não. Caso nenhum token seja passado como parâmetro, a gem utilizará o último `access_token` armazenado no cookie da aplicação.


```ruby
Keycloak::Client.get_token_by_client_credentials(client_id = '', secret = '')
```

Há alguns serviços do Keycloak como <b>reset de senha</b>, <b>cadastro de usuário</b> na tela inicial da aplicação ou até mesmo autenticação seguindo o padrão <b>OAuth 2.0</b>, que a autenticação de um usuário torna-se desnecessária. Sendo assim, podemos obter um token utilizando as credenciais da sua própria aplicação (Client) cadastrada no Keycloak. Para obter esse token, deve-se passar como parâmetro desse método o `client_id` - informado pela pessoa que cadastrou sua aplicação no Keycloak - e a `secret` de sua aplicação gerado pelo Keycloak - para gerar uma `secret`, o <b>Access Type</b> do seu Client (Aplicação) deverá estar configurado como `confidential`. Caso você não passe nenhum desses parâmetros, a gem utilizará as credenciais contidas no arquivo de instalação citado anteriormente.


```ruby
Keycloak::Client.logout(redirect_uri = '', refresh_token = '', client_id = '', secret = '', end_session_endpoint = '')
```

Quando utilizado antes da expiração da sessão do usuário logado, esse método encerra a sessão. Se o parâmetro `redirect_uri` for alimentado, então o Keycloak redirecionará a sua aplicação para a url informada após a efetuação do logout. O segundo parâmetro é o `refresh_token` obtido no momento da autenticação ou da atualização da sessão. Caso este último não seja informado, então a gem utilizará o `refresh_token` do cookie.


```ruby
Keycloak::Client.get_userinfo(access_token = '', userinfo_endpoint = '')
```

Esse método retorna informações sintéticas do usuário representado pelo `access_token` passado como parâmetro, tais como `sub` - que é o Id do usuário autenticado -, `preferred_username` - que é o nome do usuário autenticado - e `email` - que é o e-mail do usuário. Caso o parâmetro `access_token` não seja informado, então a gem obterá essa informação no cookie.


```ruby
Keycloak::Client.url_user_account
```

Retorna a <b>url</b> para acesso ao cadastro de usuários do Reino do arquivo de instalação (`keycloak.json`). Para ter acesso a tela, o Keycloak exigirá a autenticação do usuário. Após logado, e caso tenha permissão, o usuário terá acesso a suas informações cadastrais podendo inclusive alterá-las.


```ruby
Keycloak::Client.has_role?(user_role, access_token = '', client_id = '', secret = '', token_introspection_endpoint = '')
```

O método `has_role?` decodifica o JWT `access_token` e verifica se o usuário dono do token possui o <b>role</b> informado no parâmetro `user_role`. Caso o `access_token` não seja informado, então a gem utilizará o `access_token` do cookie.


```ruby
Keycloak::Client.user_signed_in?(access_token = '', client_id = '', secret = '', token_introspection_endpoint = '')
```

Esse método verifica se o `access_token` passado no parâmetro ainda está ativo. Para verificar se o usuário está ativo ou não, internamente a gem invoca o método `get_token_introspection`. Caso o `access_token` não seja informado, então a gem utilizará o `access_token` do cookie.


```ruby
Keycloak::Client.get_attribute(attribute_name, access_token = '')
```

Esse método decodifica o JWT `access_token` e retorna o valor do atributo de nome passado no parâmetro `attribute_name`. Esse atributo pode ser um <b>mapper</b> - cadastrado na seção <b>Mappers</b> do cadastro do <b>Client</b> do Reino. Caso o `access_token` não seja informado, então a gem utilizará o `access_token` do cookie.


```ruby
Keycloak::Client.token
```

Retorna o último token autenticado armazenado no cookie. Quando na aplicação é implementado o método `Keycloak.proc_cookie_token` e um usuário faz a autenticação da aplicação, esse método retornará o token desse usuário.


```ruby
Keycloak::Client.external_attributes
```

Quando implementado o método `Keycloak.proc_external_attributes`, o método `external_attributes` o retornará. A finalidade desse método é retornar os atributos específicos da aplicação não mapeados no Keycloak.


### Keycloak::Admin

O módulo `Keycloak::Admin`disponibiliza métodos que representam as [REST APIs do Keycloak](http://www.keycloak.org/docs-api/3.2/rest-api/index.html). Para a utilização dessas APIs, será necessário um `access_token` ativo, ou seja, a autenticação deverá ocorrer antes da utilização dos métodos para que um token válido seja utilizado como credencial. Caso o `access_token` não seja informado, então a gem utilizará o `access_token` do cookie. O usuário autenticado deverá ter o `role` do respectivo serviço invocado - roles do client `realm-management`, que representa o gerenciamento do reino.

Segue abaixo a lista dos métodos. O parâmetro de rota `{realm}` de todas as APIs será obtido do arquivo de instalação `keycloak.json`:


```ruby
# GET /admin/realms/{realm}/users
Keycloak::Admin.get_users(query_parameters = nil, access_token = nil)
```

`get_users` retorna uma lista de usuários, filtrada de acordo com o hash de parâmetros passado em `query_parameters`.


```ruby
# POST /admin/realms/{realm}/users
Keycloak::Admin.create_user(user_representation, access_token = nil)
```

`create_user` cria um novo usuário no Keycloak. O parâmetro `user_representation` deve ser um hash conforme o [UserRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_userrepresentation)  do Keycloak. O retorno deste método será `true` para o caso de sucesso.


```ruby
# GET /admin/realms/{realm}/users/count
Keycloak::Admin.count_users(access_token = nil)
```

`count_users` retorna a quantidade de usuários do reino.


```ruby
# GET /admin/realms/{realm}/users/{id}
Keycloak::Admin.get_user(id, access_token = nil)
```

`get_user` retorna a representação do usuário identificado pelo parâmetro `id` - que é o <b>ID</b> criado pelo Keycloak ao criar um novo usuário.


```ruby
# PUT /admin/realms/{realm}/users/{id}
Keycloak::Admin.update_user(id, user_representation, access_token = nil)
```

`update_user` atualiza o cadastro do usuário identificado pelo `id` - que é o <b>ID</b> criado pelo Keycloak ao criar um novo usuário. No parâmetro `user_representation` deverá ser uma hash com os campos que serão alterados, respeitando o [UserRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_userrepresentation) do Keycloak. O retorno deste método será `true` para o caso de sucesso.


```ruby
# DELETE /admin/realms/{realm}/users/{id}
Keycloak::Admin.delete_user(id, access_token = nil)
```

`delete_user` exclui o cadastro do usuário identificado pelo `id` - que é o <b>ID</b> criado pelo Keycloak ao criar um novo usuário. O retorno deste método será `true` para o caso de sucesso.


```ruby
# DELETE /admin/realms/{realm}/users/{id}/consents/{client}
Keycloak::Admin.revoke_consent_user(id, client_id = nil, access_token = nil)
```

`revoke_consent_user` revoga os tokens de um usuário identificado pelo `id` - que é o <b>ID</b> criado pelo Keycloak ao criar um novo usuário - no client identificado pelo parâmetro `client_id`.


```ruby
# PUT /admin/realms/{realm}/users/{id}/execute-actions-email
Keycloak::Admin.update_account_email(id, actions, redirect_uri = '', client_id = nil, access_token = nil)
```

`update_account_email` envia um e-mail de atualização da conta para o usuário representado pelo parâmetro `id`. O e-mail contém um link que o usuário poderá clicar para executar um conjunto de ações representados pelo parâmetro `actions` - que aguarda um `array` de [ações definidas pelo Keycloak](http://www.keycloak.org/docs/3.2/server_admin/topics/users/required-actions.html). Um exemplo de valor que pode ser passado para o parâmetro `actions` é `['UPDATE_PASSWORD']`, que indica que a ação que o usuário deverá tomar ao clicar o link do e-mail é de alterar a sua senha. No parâmetro `redirect_uri`, caso necessário, deverá ser passada uma <b>url</b> para que, ao término do envio do e-mail, a aplicação seja redirecionada. O parâmetro `client_id` deverá ser informado caso o Client responsável pela as ações que deverão ser executadas não seja o mesmo do arquivo de instalação `keycloak.json`.


```ruby
# GET /admin/realms/{realm}/users/{id}/role-mappings
Keycloak::Admin.get_role_mappings(id, access_token = nil)
```

`get_role_mappings` retorna todas as <b>Role Mappings</b> do reino atribuídas ao usuário identificado pelo parâmetro `id`, independentemente do Client.

```ruby
# GET /admin/realms/{realm}/groups
Keycloak::Admin.get_groups(query_parameters = nil, access_token = nil)
```

`get_groups` retorna a lista de [GroupRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_grouprepresentation) do reino. O parâmetro opcional  `query_parameters` espera um hash com propriedades correspondentes a qualquer um dos [query parameters](https://www.keycloak.org/docs-api/3.2/rest-api/index.html#_groups_resource) aceitos pela API.


```ruby
# GET /admin/realms/{realm}/clients
Keycloak::Admin.get_clients(query_parameters = nil, access_token = nil)
```

`get_clients` retorna uma lista de [ClientRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_clientrepresentation) Clients pertencentes ao reino. O parâmetro `query_parameters` espera um hash com os atributos `clientId` - caso deseje que a lista seja filtrada pelo `client_id` - e `viewableOnly` - para filtrar se os Clients de administração do Keycloak serão ou não retornados na lista.


```ruby
# GET /admin/realms/{realm}/clients/{id}/roles
Keycloak::Admin.get_all_roles_client(id, access_token = nil)
```

`get_all_roles_client` retorna uma lista de [RoleRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_rolerepresentation) com todos os <b>roles</b> do client identificado pelo parâmetro `id` - deve ser passado nesse parâmetro o `ID` do Client e não o `client_id`.


```ruby
# GET /admin/realms/{realm}/clients/{id}/roles/{role-name}
Keycloak::Admin.get_roles_client_by_name(id, role_name, access_token = nil)
```

`get_roles_client_by_name` retorna a [RoleRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_rolerepresentation) do role identificado pelo parâmetro `role_name` - que é o nome do role.


```ruby
# POST /admin/realms/{realm}/users/{id}/role-mappings/clients/{client}
Keycloak::Admin.add_client_level_roles_to_user(id, client, role_representation, access_token = nil)
```

`add_client_level_roles_to_user` insere um <b>role</b> do Client (representado pelo parâmetro `client`) ao usuário representado pelo parâmetro `id`. O parâmetro `role_representation` deverá receber um `array` de [RoleRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_rolerepresentation) que serão inseridos no usuário. Em caso de sucesso, o retorno será `true`.


```ruby
# DELETE /admin/realms/{realm}/users/{id}/role-mappings/clients/{client}
Keycloak::Admin.delete_client_level_roles_from_user(id, client, role_representation, access_token = nil)
```

`delete_client_level_roles_from_user` exclui um <b>Client-Role</b> (representado pelo parâmetro `client`) do usuário representado pelo parâmetro `id`. O parâmetro `role_representation` deverá receber um `array` de [RoleRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_rolerepresentation) que serão retirados do usuário. Em caso de sucesso, o retorno será `true`.


```ruby
# GET /admin/realms/{realm}/users/{id}/role-mappings/clients/{client}
Keycloak::Admin.get_client_level_role_for_user_and_app(id, client, access_token = nil)
```

`get_client_level_role_for_user_and_app` retorna uma lista de [RoleRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_rolerepresentation) dos <b>Client-Roles</b> do Client representado pelo parâmetro `client` vinculados ao usuário representado pelo parâmetro `id`.


```ruby
Keycloak::Admin.update_effective_user_roles(id, client_id, roles_names, access_token = nil)
```

`update_effective_user_roles` não está na lista de <b>Admin APIs</b> do Keycloak. Este método vincula ao usuário representado pelo parâmetro `id` todos os roles passados em um `array` no parâmetro `roles_names`. Os roles passados no parâmetro `roles_names` deverão pertencer ao Client representado pelo parâmetro `client_id`. Caso o usuário possua o vínculo com um role que não esteja no parâmetro `roles_names`, esse vínculo será removido, pois a finalidade desse método é que o usuário assuma efetivamente os roles passados nesse parâmetro. Em caso de sucesso, o retorno será `true`.


```ruby
PUT /admin/realms/{realm}/users/{id}/reset-password
Keycloak::Admin.reset_password(id, credential_representation, access_token = nil)
```

`reset_password` altera a senha do usuário representado pelo parâmetro `id`. A nova senha é representada pelo parâmetro `credential_representation`, que trata-se de um conjunto de informações formatadas segundo a seção [CredentialRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_credentialrepresentation) do manual de APIs do Keycloak.


```ruby
GET /admin/realms/{realm}/groups/{id}/role-mappings/clients/{client}/composite
Keycloak::Admin.get_effective_client_level_role_composite_user(id, client, access_token = nil)
```

`get_effective_client_level_role_composite_user` retorna uma lista (array) de [RoleRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_rolerepresentation) de um <b>Grupo</b> representado pelo parâmetro `id` atrelados a um <b>Client</b> representado pelo parâmetro `client`.


Caso tenha algum serviço no manual [Keycloak Admin REST API](http://www.keycloak.org/docs-api/3.2/rest-api/index.html) que não tenha sido implementado na gem, há uma possibilidade do mesmo ser invocado utilizando os <b>Generics Methods</b> do model `Keycloak::Admin`. Os <b>Generics Methods</b> te possibilita fazer a requisição de qualquer uma das APIs, seja ela `GET`, `POST`, `PUT` ou `DELETE`, passando os parâmetros da requisição como `hashes` nos parâmetros `query_parameters` e `body_parameter` dos <b>Generics Methods</b>.
<br>
Veja a seguir os <b>Generics Methods</b>:
<br>

```ruby
Keycloak::Admin.generic_get(service, query_parameters = nil, access_token = nil)
```

`generic_get` permite que você faça requisições de serviços `GET` do <b>Keycloak</b>. A parte da URI que identifica o serviço deve ser passada no parâmetro `service`, já com os parâmetros de rota (como o `{client}`, por exemplo) devidamente substituídos. No parâmetro `query_parameters` você poderá passar um `hash` contendo os <b>Queries Parameters</b> da requisição.<br>
Exemplo:
```ruby
    Keycloak::Admin.generic_get("users/", {email: 'admin@test.com'}, "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldU...")
```



```ruby
Keycloak::Admin.generic_post(service, query_parameters, body_parameter, access_token = nil)
```

`generic_post` permite que você faça requisições de serviços `POST` do <b>Keycloak</b>. A parte da URI que identifica o serviço deve ser passada no parâmetro `service`, já com os parâmetros de rota (como o `{client}`, por exemplo) devidamente substituídos. No parâmetro `query_parameters` você poderá passar um `hash` contendo os <b>Query Parameters</b> da requisição. No parâmetro `body_parameter` você poderá passar um `hash` contendo os <b>Body Parameters</b> da requisição.<br>
Exemplo:
```ruby
    Keycloak::Admin.generic_post("users/", nil, { username: "admin", email: "admin@test.com", enabled: true }, "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldU...")
```


```ruby
Keycloak::Admin.generic_put(service, query_parameters, body_parameter, access_token = nil)
```

`generic_put` permite que você faça requisições de serviços `PUT` do <b>Keycloak</b>. A parte da URI que identifica o serviço deve ser passada no parâmetro `service`, já com os parâmetros de rota (como o `{client}`, por exemplo) devidamente substituídos. No parâmetro `query_parameters` você poderá passar um `hash` contendo os <b>Query Parameters</b> da requisição. No parâmetro `body_parameter` você poderá passar um `hash` contendo os <b>Body Parameters</b> da requisição.


```ruby
Keycloak::Admin.generic_delete(service, query_parameters = nil, body_parameter = nil, access_token = nil)
```

`generic_delete` permite que você faça requisições de serviços `DELETE` do <b>Keycloak</b>. A parte da URI que identifica o serviço deve ser passada no parâmetro `service`, já com os parâmetros de rota (como o `{client}`, por exemplo) devidamente substituídos. No parâmetro `query_parameters` você poderá passar um `hash` contendo os <b>Query Parameters</b> da requisição. No parâmetro `body_parameter` você poderá passar um `hash` contendo os <b>Body Parameters</b> da requisição.



### Keycloak::Internal

O módulo `Keycloak::internal` disponibiliza métodos criados para facilitar a interação entre a aplicação e o <b>Keycloak</b>. Partindo das informações encontradas no arquivo de instalação `keycloak.json`, todos os métodos invocados serão autenticados automaticamente, utilizando as credências da aplicação (`grant_type = client_credentials`), dependendo assim dos <b>roles</b> atribuídos a mesma para que o retorno da requisição seja autorizado.


```ruby
Keycloak::Internal.get_users(query_parameters = nil, client_id = '', secret = '')
```

`get_users` invoca o método `Keycloak::Admin.get_users` que, por sua vez, retorna uma lista de usuários, filtrada de acordo com o hash de parâmetros passado em `query_parameters`.

```ruby
Keycloak::Internal.get_groups(query_parameters = nil, client_id = '', secret = '')
```

`get_groups` invoca o método `Keycloak::Admin.get_groups` que retonar a hierarquia dos grupos do reino, filtrado de acordo com o hash passado no parâmetro `query_parameters`.


```ruby
Keycloak::Internal.change_password(user_id, redirect_uri = '', client_id = '', secret = '')
```

`change_password` invocará a API `PUT /admin/realms/{realm}/users/{id}/execute-actions-email` do Keycloak requisitando a action `UPDATE_PASSWORD`. Isso fará com que o Keycloak dispare um e-mail para o usuário representado pelo parâmetro `user_id`. O parâmetro `redirect_uri` é opcional. Se não for preenchido, então não haverá nenhum link para clicar após a ação de reset de senha ter sido concluída.


```ruby
Keycloak::Internal.get_user_info(user_login, whole_word = false, client_id = '', secret = ''))
```

`get_user_info`, baseado no parâmetro `user_login`, que poderá recepcionar o `username` ou o `email` do usuário, retornará uma lista (array) de [UserRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_userrepresentation) no caso em que o parâmetro `whole_word` for `false`, ou retornará um [UserRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_userrepresentation) quando o parâmetro `whole_word` for `true`. O parâmetro `whole_word` indica se o método deverá considerar usuários que tenham no `username` ou `email` parte da expressão passada no parâmetro `user_login` - para os casos de `whole_word = false` -, ou que tenha exatamente a expressão passada nesse parâmetro - para os casos de `whole_word = true`.


```ruby
Keycloak::Internal.forgot_password(user_login, redirect_uri = '', client_id = '', secret = '')
```

`forgot_password` invocará o método `Keycloak::Internal.change_password` após invocar o método `Keycloak::Internal.get_user_info` - passando no parâmetro `user_login` do método descrito o parâmetro `user_login`deste tópico e passando `true` no parâmetro `whole_word`. A utilização deste método é indicado para os casos de aplicações permitam o reset da senha dos usuários sem que o mesmo esteja logado.


```ruby
Keycloak::Internal.exists_name_or_email(value, user_id = '', client_id = '', secret = '')
```

`exists_name_or_email` verifica se no reino já existe algum usuário com `username` ou o `email` passado no parâmetro `value`. O parâmetro `user_id` serve para passar o `ID` de um usuário nos casos em que deseja-se alterar o `username` ou o `email` do mesmo, para que assim sejam considerados na verificação do `username` e do `email` usuários diferentes do usuário com o `ID` informado em `user_id`.


```ruby
Keycloak::Internal.get_logged_user_info(client_id = '', secret = '')
```

`get_logged_user_info` retorna o [UserRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_userrepresentation) do usuário logado na aplicação.


```ruby
# GET /admin/realms/{realm}/users
Keycloak::Internal.logged_federation_user?(client_id = '', secret = '')
```

`logged_federation_user?` incova o método `Keycloak::Internal.get_logged_user_info` e verifica se o mesmo é um <b>Federation User</b> (um usuário do LDAP por exemplo).


```ruby
# GET /admin/realms/{realm}/users
Keycloak::Internal.create_starter_user(username, password, email, client_roles_names, proc = nil, client_id = '', secret = '')
```

`create_starter_user` é indicado para aplicações que permitam a criação de novos usuários sem que um usuário esteja logado ou até mesmo para criar novos usuários a partir do `rake db:seed`. Nos parâmetros `username`, `password` e `email` devem ser passados o nome, a senha, e o e-mail do usuário, respectivamente. No parâmetro `client_roles_names`deve ser passado uma lista (array) com o nome dos `roles` do Client que serão atribuídos ao usuário. O parâmetro `proc` trata-se de um método <b>lambda</b> que disponibilizará como parâmetro a [UserRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_userrepresentation) do usuário criado para que sejam definidas ações por parte da aplicação. Esse método terá como retorno o mesmo retorno do método do parâmetro `proc` se o mesmo for definido, caso contrário retornará a [UserRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_userrepresentation) do usuário criado.


```ruby
Keycloak::Internal.get_client_roles(client_id = '', secret = '')
```

`get_client_roles` retornará uma lista (array) de [RoleRepresentation](http://www.keycloak.org/docs-api/3.2/rest-api/index.html#_rolerepresentation) do Client indicado no parâmetro `client_id` ou, na falta desse, pelo Client do arquivo de instalação `keycloak.json`.


```ruby
Keycloak::Internal.get_client_user_roles(user_id, client_id = '', secret = '')
```

`get_client_user_roles` invocará o método `Keycloak::Admin.get_effective_client_level_role_composite_user` considerando o Client indicado no parâmetro `client_id` ou, na falta desse, pelo Client do arquivo de instalação `keycloak.json` e o usuário representado pelo parâmetro `user_id`.


```ruby
Keycloak::Internal.has_role?(user_id, user_role, client_id = '', secret = '')
```

`has_role?` informará se o usuário representado pelo parâmetro `user_id` possui o <b>role</b> com o nome representado pelo parâmetro `user_role`.
