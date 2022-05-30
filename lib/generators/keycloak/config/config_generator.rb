module Keycloak
  module Generators
    class ConfigGenerator < Rails::Generators::Base
      source_root(__dir__)
      def copy_initializer
        copy_file '../../keycloak.rb', 'config/initializers/keycloak.rb'
      end
    end
  end
end
