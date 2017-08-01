class InitializerGenerator < Rails::Generators::Base
  def create_initializer_file
    create_file "config/initializers/keycloak.rb" do
			proxy = ""
			generate_request_exception = true
			"# Set proxy to connect in keycloak server
			 Keycloak::proxy = #{proxy}
			 # If true, then all request exception will explode in application (this is the default value)
			 Keycloak::generate_request_exception = #{generate_request_exception}
			 # controller that manage the user session
			 Keycloak::keycloak_controller = 'session'"
    end
  end
end