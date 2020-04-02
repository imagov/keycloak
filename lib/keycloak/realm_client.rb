# frozen_string_literal: true

module Keycloak
  class RealmClient
    def initialize(realm, server_url:)
      @realm = realm
      @server_url = server_url
    end

    def realm_admin_url
      "#{@server_url}/admin/realms/#{@realm}"
    end
  end
end
