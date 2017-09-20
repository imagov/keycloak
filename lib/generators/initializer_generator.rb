class InitializerGenerator < Rails::Generators::Base
	source_root(File.expand_path(File.dirname(__FILE__)))

	def copy_initializer
		copy_file 'keycloak.rb', 'config/initializers/keycloak.rb'
	end

end