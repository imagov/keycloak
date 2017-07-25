require "keycloak/version"
require 'rest-client'
require 'json'
require 'jwt'
require 'base64'
require 'uri'

module Keycloak

  class << self
		attr_accessor :proxy, :generate_request_exception
	end


	def self.explode_exception
		if Keycloak::generate_request_exception == nil
			Keycloak::generate_request_exception = true
		end
		Keycloak::generate_request_exception
	end

	module Client

		class << self
			attr_reader :user, :password, :realm, :url, :clientID, :auth_server_url,
									:secret, :configuration, :public_key, :decoded_access_token,
									:token, :token_introspection, :decoded_refresh_token,
									:active, :decoded_id_token, :userinfo

			attr_accessor :admin
		end

		def self.teste
			puts 'testeeeeeeeeeeee'
		end

		KEYCLOAK_JSON_FILE = 'keycloak.json'

		def self.get_token(user, password)
			setup_module
			reset_active

			@user, @password = user, password

			payload = {'client_id' => @client_id,
								'client_secret' => @secret,
								'username' => @user,
								'password' => @password,
								'grant_type' => 'password'
								}

			mount_request_token(payload)
		end

		def self.get_token_by_code(code, redirect_uri)
			reset_active

			payload = {'client_id' => @client_id,
								'client_secret' => @secret,
								'code' => code,
								'grant_type' => 'authorization_code',
								'redirect_uri' => redirect_uri
								}

			mount_request_token(payload)
		end

		def self.get_token_introspection(refresh = false)
			unless refresh
				payload = {'token' => @token["access_token"]}
			else
				payload = {'token' => @token["refresh_token"]}
			end

			authorization = Base64.strict_encode64("#{@client_id}:#{@secret}")
			authorization = "Basic #{authorization}"

			header = {'Content-Type' => 'application/x-www-form-urlencoded',
								'authorization' => authorization}

			_request = -> do
				RestClient.post(@configuration['token_introspection_endpoint'], payload, header){|response, request, result|
					case response.code
					when 200..399
						@token_introspection = JSON response.body
						@active = @token_introspection['active']
						@token_introspection
					else
						reset_active
						response.return!
					end
				}
			end

			exec_request _request
		end

		def self.url_login_redirect(redirect_uri, response_type = 'code')
			p = URI.encode_www_form({:response_type => response_type, :client_id => @client_id, :redirect_uri => redirect_uri})
			"#{@configuration['authorization_endpoint']}?#{p}"
		end

		def self.url_logout(redirect_uri)
			"#{@configuration['end_session_endpoint']}?redirect_uri=#{redirect_uri}"
		end

		def self.get_userinfo
			payload = {'access_token' => @token["access_token"]}

			header = {'Content-Type' => 'application/x-www-form-urlencoded'}

			_request = -> do
				RestClient.post(@configuration['userinfo_endpoint'], payload, header){|response, request, result|
					case response.code
					when 200
						@userinfo = JSON response.body
						@userinfo
					else
						response.return!
					end
				}
			end

			exec_request _request
		end

		def self.url_user_account
			"#{@url}/realms/#{@realm}/account"
		end

		def self.get_installation
			if File.exists?(KEYCLOAK_JSON_FILE)
				installation = JSON File.read(KEYCLOAK_JSON_FILE)
				@realm = installation["realm"]
				@url = installation["auth-server-url"]
				@client_id = installation["resource"]
				@secret = installation["credentials"]["secret"]
				@public_key = installation["realm-public-key"]
				@auth_server_url = installation["auth-server-url"]
				reset_active
				openid_configuration
			else
				raise "#{KEYCLOAK_JSON_FILE} not found."
			end
		end

		private

			def self.setup_module
				if Keycloak::proxy == nil
					Keycloak::proxy = ''
				end
				get_installation
			end

			def self.exec_request(proc_request)
				if Keycloak::explode_exception
					proc_request.call
				else
					begin
						proc_request.call
					rescue RestClient::ExceptionWithResponse => err
						err.response
					end
				end
			end

			def self.openid_configuration
				RestClient.proxy = Keycloak::proxy unless Keycloak::proxy.empty?
				full_url = "#{@url}/realms/#{@realm}/.well-known/openid-configuration"
				_request = -> do
					RestClient.get full_url
				end
				response = exec_request _request
				if response.code == 200
					@configuration = JSON response.body
				else
					response.return!
				end
			end

			def self.reset_active
				@active = false
			end

			def self.mount_request_token(payload)
				header = {'Content-Type' => 'application/x-www-form-urlencoded'}

				_request = -> do
					RestClient.post(@configuration['token_endpoint'], payload, header){|response, request, result|
						case response.code
						when 200
							@active = true
							@token = JSON response.body
							@decoded_access_token = JWT.decode @token["access_token"], @public_key, false, { :algorithm => 'RS256' }
							@decoded_refresh_token = JWT.decode @token["refresh_token"], @public_key, false, { :algorithm => 'RS256' }
							@decoded_id_token = JWT.decode @token["id_token"], @public_key, false, { :algorithm => 'RS256' }
							#@admin = Admin.new(@auth_server_url, @realm,  @token["access_token"])
							Keycloak::Admin::setup_admin(@auth_server_url, @realm,  @token["access_token"])
							@token
						else
							response.return!
						end
					}
				end

				exec_request _request
			end

	end

	# Os recursos desse module (admin) serão utilizadas apenas por usuários que possuem as roles do client realm-management
	module Admin

		class << self
			attr_reader :access_token, :auth_server_url, :realm, :last_response
		end

		def self.setup_admin(auth_server_url, realm, access_token)
			@auth_server_url = auth_server_url
			@access_token = access_token
			@realm = realm
		end

		def self.get_users( queryParameters = nil)
			generic_get("users/", queryParameters)
		end

		def self.create_user(userRepresentation)
			generic_post("users/", nil, userRepresentation)
		end

		def self.count_users
			generic_get("users/count/")
		end

		def self.get_user(id)
			generic_get("users/#{id}")
		end

		def self.update_user(id, userRepresentation)
			generic_update("users/#{id}", nil, userRepresentation)
		end

		def self.delete_user(id)
			generic_delete("users/#{id}")
		end

		def self.revoke_consent_user(id, clientID)
			generic_delete("users/#{id}/consents/#{clientID}")
		end

		def self.update_account_email(id, redirectUri, clientID, actions)
			generic_update("users/#{id}/execute-actions-email", {:redirect_uri => redirectUri, :client_id => clientID}, actions)
		end

		# Generics methods

		def self.generic_get(service, queryParameters = nil)
			generic_request(service, queryParameters, 'GET')
		end

		def self.generic_post(service, queryParameters, bodyParameter)
			generic_request(service, bodyParameter, 'POST')
		end

		def self.generic_update(service, queryParameters, bodyParameter)
			generic_request(service, queryParameters, bodyParameter, 'PUT')
		end

		def self.generic_delete(service)
			generic_request(service, nil, 'DELETE')
		end

		private

			def self.base_url
				@auth_server_url + "/admin/realms/#{@realm}/"
			end

			def self.generic_request(service, queryParameters, bodyParameter, method)
				final_url = base_url + service

				header = {'Content-Type' => 'application/x-www-form-urlencoded',
									'Authorization' => "Bearer #{@access_token}"}

				if queryParameters
					parameters = URI.encode_www_form(queryParameters)
					final_url = final_url << '?' << parameters
				end

				case method.upcase
				when 'GET'
					_request = -> do
						RestClient.get(final_url, header){|response, request, result|
							rescue_response(response)
						}
					end
				when 'POST', 'PUT'
					header["Content-Type"] = 'application/json'
					parameters = JSON.generate bodyParameter
					_request = -> do
						case method.upcase
						when 'POST'
							RestClient.post(final_url, parameters, header){|response, request, result|
								rescue_response(response)
							}
						else
							RestClient.put(final_url, parameters, header){|response, request, result|
								rescue_response(response)
							}
						end
					end
				when 'DELETE'
					_request = -> do
						RestClient.delete(final_url, header){|response, request, result|
							rescue_response(response)
						}
					end
				else
					raise
				end

				_request.call

			end

			def self.rescue_response(response)
				@last_response = response
				case @last_response.code
				when 200..399
					if @last_response.body.empty?
						true
					else
						@last_response.body
					end
				else
					if Keycloak::explode_exception
						@last_response.return!
					else
						begin
							@last_response.return!
						rescue RestClient::ExceptionWithResponse => err
							err.response
						rescue Exception => e
							e.message
						end
					end
				end
			end

	end

end
