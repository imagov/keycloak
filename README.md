# Keycloak
A gem Keycloak foi desenvolvida para integrar aplicações e serviços ao sistema [Keycloak](http://www.keycloak.org/) da [Red Hat](https://www.redhat.com) para controle de usuários, autenticação, autorização e sessão.

O seu desenvolvimento foi baseado na versão 3.2 do Keycloak, cuja documentação pode ser encontrada [aqui](http://www.keycloak.org/archive/documentation-3.2.html).

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'keycloak'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install keycloak

## Utilização

Considerando que você já possua um ambiente do Keycloak configurado e a gem já instalada, o próximo passo é definir como será a autenticação da aplicação. O Keycloak trabalha com os principais protocolos de autenticação, tais como o OpenID Connect, Oauth 2.0 e SAML 2.0, integrando acesso a sistemas via Single-Sign On, podendo inclusive disponibilizar acessos a usuários LDAP ou Active Directory.

Ao cadastrar um Reino e também um Client no seu ambiente Keycloak, será necessário fazer o download do arquivo de instalação do Client para dentro da pasta raiz da aplicação, para que a gem obtenha as informações necessárias para interagir com o Keycloak. Para fazer esse download, basta acessar o cadastro de seu Client, clicar na aba <b>Installation</b>, selecionar <b>Keycloak OIDC JSON</b> no campo <b>Format option</b> e clicar em <b>Download</b>.

A gem possui um módulo principal chamado <b>Keycloak</b>. Dentro desse módulo há três outros módulos: <b>Client</b>, <b>Admin</b> e <b>Internal</b>.

### Client

Esse módulo possui os métodos que representam as APIs de <b>endpoints</b>. Esses serviços são fundamentais para a criação e atualização de tokens, efetuação de login e logout, e, também para a obtenção de informações sintéticas de um usuário logado. O que habilita a gem a fazer uso de todos esses serviços é o arquivo de instalação do client citado anteriormente.

Vamos ao detalhamento de cada um desses métodos:

```ruby
Keycloak::Client.get_token(user, password)
```

Caso você opte por efetuar a autenticação dos usuários utilizando a tela da sua própria aplicação, então utilize esse método. Basta invocá-lo no método de login no <b>controller</b> definido com o controlador de sessão de sua aplicação, passando como parâmetro o <b>usuário</b> e a <b>senha</b> informados pelo usuário. Caso a autenticação seja válida, então será retornado um JSON contendo entre as informações principais o <b>access_token</b> e o <b>refresh_token</b>.


```ruby
Keycloak::Client.url_login_redirect(redirect_uri, response_type = 'code')
```

Para efetuar a autenticação dos usuários de sua aplicação utilizando um template configurado no Keycloak, redirecione a requisição para a url retornada nesse método. Passe como parâmetro a url que o usuário terá acesso no caso de êxito na autenticação(<b>redirect_uri</b>) e também o tipo de resposta (<b>response_type</b>), que caso não informado, a gem assumirá o valor <b>code</b>. Caso a autenticação seja bem sucedida, então será retornado um <b>code</b> que te habilitará a requisitar um token ao Keycloak.

```ruby
Keycloak::Client.get_token_by_code(code, redirect_uri)
```

Ao utilizar o método Keycloak::Client.url_login_redirect para obter um <b>code</b>, passe-o como parâmetro neste método para que o Keycloak retorne um token, efetuando assim o login do usuário na aplicação. O segundo parâmetro (redirect_uri) deve ser passado para que, ao disponibilizar um token, o Keycloak redirecione para a url informada.

```ruby
Keycloak::Client.get_token_by_refresh_token(refreshToken = '')
```

Quando o usuário já estiver logado e a sua aplicação acompanhar internamente o tempo de expiração do token fornecido pelo Keycloak, então esse método poderá ser utilizado para a renovação desse token, caso o mesmo ainda seja válido. Para isso, bastar passar como parãmetro o <b>refresh_token</b>. Caso não seja informado o <b>refresh_token</b>, a gem utilizará o <b>refresh_token</b> armazenado no cookie da aplicação.

```ruby
Keycloak::Client.get_token_introspection(token = '')
```

Esse método retorna a as informações da sessão do <b>token</b> passado como parâmetro. Entre as informações retornadas, a mais importante é o campo <b>active</b>, pois ele informa se a sessão do token passado no parâmetro é ativo ou não. Isso auxiliará a sua aplicação a controlar se a sessão do usuário logado expirou ou não. Caso nenhum token seja passado como parâmetro, a gem utilizará o último <b>access_token</b> armazenado no cookie da aplicação.
