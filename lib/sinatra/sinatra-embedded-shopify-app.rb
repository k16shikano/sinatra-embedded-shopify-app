# frozen_string_literal: true

require 'sinatra/base'
require 'sinatra/activerecord'
require 'sinatra/cookies'
require 'attr_encrypted'
require 'active_support/all'
require 'shopify_api'

# Sinatra
module Sinatra
  # Shopify
  module Shopify
    # Methods
    module Methods
      # designed to be overridden
      def after_shopify_auth; end

      # for the app bridge initializer
      def shop_host
        (session[:shopify][:host]).to_s
      end

      def shopify_session
        return_to = request.path
        return_params = request.params

        if no_session?
          authenticate(return_to, return_params)

        elsif different_shop?
          clear_session
          authenticate(return_to, return_params)

        else
          shop_name = session[:shopify][:shop]
          this_session = session[:shopify][:outh_session]
          activate_shopify_api(shop_name, this_session)
          yield shop_name
        end
      rescue ActiveResource::UnauthorizedAccess
        clear_session

        shop = Shop.find_by(shopify_domain: shop_name)
        shop.shopify_token = nil
        shop.save

        redirect request.path
      end

      private

      def authenticate(_return_to = '/', return_params = nil)
        session[:return_params] = return_params if return_params

        if (shop_name = sanitized_shop_param(params))
          redirect "/install?shop=#{shop_name}"
        else
          redirect '/install'
        end
      end

      def base_url
        request_protocol = request.secure? ? 'https' : 'http'
        "#{request_protocol}://#{request.env['HTTP_HOST']}"
      end

      def no_session?
        !session.key?(:shopify)
      end

      def different_shop?
        params[:shop].present? && session[:shopify][:shop] != sanitized_shop_param(params)
      end

      def clear_session
        session.delete(:shopify)
        session.clear
      end

      def activate_shopify_api(shop_name, token)
        ShopifyAPI::Context.activate_session(outh_session)
      end

      def receive_webhook
        return unless verify_shopify_webhook

        shop_name = request.env['HTTP_X_SHOPIFY_SHOP_DOMAIN']
        webhook_body = ActiveSupport::JSON.decode(request.body.read.to_s)
        yield shop_name, webhook_body
        status 200
      end

      def sanitized_shop_param(params)
        return unless params[:shop].present?

        name = params[:shop].to_s.strip
        name += '.myshopify.com' if !name.include?('myshopify.com') && !name.include?('.')
        name.gsub!('https://', '')
        name.gsub!('http://', '')

        u = URI("http://#{name}")
        u.host.ends_with?('.myshopify.com') ? u.host : nil
      end

      def verify_shopify_webhook
        data = request.body.read.to_s
        calculated_hmac = Base64.strict_encode64(OpenSSL::HMAC.digest('sha256', settings.shared_secret, data))
        request.body.rewind

        if calculated_hmac == request.env['HTTP_X_SHOPIFY_HMAC_SHA256']
          true
        else
          puts 'Shopify Webhook verification failed!'
          false
        end
      end
    end

    # needs to be dynamic to incude the current shop
    class ContentSecurityPolicy < Rack::Protection::Base
      def csp_policy(env)
        "frame-ancestors 'self' #{current_shop(env)} https://admin.shopify.com;"
      end

      def call(env)
        status, headers, body = @app.call(env)
        header = 'Content-Security-Policy'
        headers[header] ||= csp_policy(env) if html? headers
        [status, headers, body]
      end

      private

      def current_shop(env)
        s = session(env)
        if s.has_key?('return_params')
          "https://#{s['return_params']['shop']}"
        elsif s.has_key?(:shopify)
          "https://#{s[:shopify][:shop]}"
        end
      end

      def html?(headers)
        return false unless (header = headers.detect { |k, _v| k.downcase == 'content-type' })

        options[:html_types].include? header.last[%r{^\w+/\w+}]
      end
    end

    def shopify_webhook(route, &blk)
      settings.webhook_routes << route
      post(route) do
        receive_webhook(&blk)
      end
    end

    def self.registered(app)
      app.helpers Shopify::Methods
      app.register Sinatra::ActiveRecordExtension

      app.set :database_file, File.expand_path('config/database.yml')

      app.set :erb, layout: :'layouts/application'
      app.set :views, File.expand_path('views')
      app.set :public_folder, File.expand_path('public')
      app.enable :inline_templates

      app.set :protection, except: :frame_options

      app.set :api_version, '2023-10'
      app.set :scope, 'read_products, read_orders'

      app.set :api_key, ENV['SHOPIFY_API_KEY']
      app.set :shared_secret, ENV['SHOPIFY_SHARED_SECRET']
      app.set :secret, ENV['SECRET']

      # csrf needs to be disabled for webhook routes
      app.set :webhook_routes, ['/uninstall']

      # add support for put/patch/delete
      app.use Rack::MethodOverride

      app.use Rack::Session::Cookie, key: 'rack.session',
                                     path: '/',
                                     secure: true,
                                     same_site: 'None',
                                     secret: app.settings.secret,
                                     expire_after: 60 * 30 # half an hour in seconds

      app.use Shopify::ContentSecurityPolicy

      app.use Rack::Protection::AuthenticityToken, allow_if: lambda { |env|
        app.settings.webhook_routes.include?(env['PATH_INFO'])
      }

      ShopifyAPI::Context.setup(
        api_key: app.settings.api_key,
        api_secret_key: app.settings.shared_secret,
        host_name: app.settings.hostname,
        scope: app.settings.scope,
        is_embedded: true,
        is_private: false,
        api_version: app.settings.api_version
      )

      app.get '/install' do
        shop_name = sanitized_shop_param(params)
        if ShopifyAPI::Context.embedded? && (!params[:embedded].present? || params[:embedded] != "1")
          auth_response = ShopifyAPI::Auth::Oauth.begin_auth(shop: shop_name, redirect_path: "/auth/shopify/callback")
          session[auth_response[:cookie].name] = auth_response[:cookie].value
          redirect auth_response[:auth_route]
        else
          erb :oauth_callback, locals: { redirectUrl: "https://#{shop_name}/api/auth", shop_host: shop_host }
        end
      end

      app.get '/auth/shopify/callback' do
        auth_query = ShopifyAPI::Auth::Oauth::AuthQuery.new(
                  code: params['code'], host: params['host'], timestamp: params['timestamp'],
                  state: params['state'], hmac: params['hmac'], shop: params['shop'])
        begin
          auth_result = ShopifyAPI::Auth::Oauth.validate_auth_callback(
            cookies: session.to_h,
            auth_query: auth_query
          )
          session[auth_result[:cookie].name] = auth_result[:cookie].value
          p "OAuth complete! New access token: #{auth_result[:session].access_token}"
          
          shop = Shop.find_or_initialize_by(shopify_domain: params['shop'])
          shop.shopify_token = auth_result[:session].access_token
          shop.save!

          session[:shopify] = {
            shop: params['shop'],
            host: params['host'],
            token: auth_result[:session].access_token,
            outh_session: auth_result[:session]
          }

          after_shopify_auth()

          return_params = session[:return_params]
          session.delete(:return_params)

          return_to = '/'
          return_to += "?#{return_params.to_query}" if return_params.present?
          redirect return_to

        rescue => e
          p e.message
        end
      end
    end
  end

  register Shopify
end

# Shop
class Shop < ActiveRecord::Base
  def self.secret
    @secret ||= ENV['SECRET']
  end

  attr_encrypted :shopify_token,
    key: secret,
    attribute: 'token_encrypted',
    mode: :single_iv_and_salt,
    algorithm: 'aes-256-cbc',
    insecure_mode: true

  validates_presence_of :shopify_domain
  validates_presence_of :shopify_token, on: :create
end
