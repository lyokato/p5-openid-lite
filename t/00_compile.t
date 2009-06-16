use strict;
use Test::More tests => 69;
BEGIN { 
    # core
    use_ok('OpenID::Lite');
    use_ok('OpenID::Lite::Identifier');
    use_ok('OpenID::Lite::Association');
    use_ok('OpenID::Lite::Identifier');
    use_ok('OpenID::Lite::DH');
    use_ok('OpenID::Lite::Nonce');
    use_ok('OpenID::Lite::Realm');
    use_ok('OpenID::Lite::Util::XRI');
    use_ok('OpenID::Lite::Util::URI');

    use_ok('OpenID::Lite::SessionHandler');
    use_ok('OpenID::Lite::SessionHandlers');
    use_ok('OpenID::Lite::SessionHandler::DH');
    use_ok('OpenID::Lite::SessionHandler::DH::SHA1');
    use_ok('OpenID::Lite::SessionHandler::DH::SHA256');
    use_ok('OpenID::Lite::SessionHandler::NoEncryption');

    use_ok('OpenID::Lite::SignatureMethod');
    use_ok('OpenID::Lite::SignatureMethods');
    use_ok('OpenID::Lite::SignatureMethod::HMAC_SHA1');
    use_ok('OpenID::Lite::SignatureMethod::HMAC_SHA256');

    # message
    use_ok('OpenID::Lite::Message');
    use_ok('OpenID::Lite::Message::Decoder');
    use_ok('OpenID::Lite::Message::Decoder::Apache');
    use_ok('OpenID::Lite::Message::Decoder::CGI');
    use_ok('OpenID::Lite::Message::Decoder::Hash');
    use_ok('OpenID::Lite::Message::Decoder::Mojo');

    # agent
    use_ok('OpenID::Lite::Agent::Dump');
    #use_ok('OpenID::Lite::Agent::Paranoid');


    # constants
    use_ok('OpenID::Lite::Constants::AssocType');
    use_ok('OpenID::Lite::Constants::CheckIDResponse');
    use_ok('OpenID::Lite::Constants::ModeType');
    use_ok('OpenID::Lite::Constants::Namespace');
    use_ok('OpenID::Lite::Constants::ProviderResponseType');
    use_ok('OpenID::Lite::Constants::SessionType');
    use_ok('OpenID::Lite::Constants::Yadis');

    # relyingparty

    # discovery
    use_ok('OpenID::Lite::RelyingParty::Discover::Method::Base');
    use_ok('OpenID::Lite::RelyingParty::Discover::Method::XRI');
    use_ok('OpenID::Lite::RelyingParty::Discover::Method::HTML');
    use_ok('OpenID::Lite::RelyingParty::Discover::Method::Yadis');
    use_ok('OpenID::Lite::RelyingParty::Discover::Method::URL');
    use_ok('OpenID::Lite::RelyingParty::Discover::Service');
    use_ok('OpenID::Lite::RelyingParty::Discover::Service::Builder');
    use_ok('OpenID::Lite::RelyingParty::Discover::FetchResult');
    use_ok('OpenID::Lite::RelyingParty::Discover::Fetcher::HTML');
    use_ok('OpenID::Lite::RelyingParty::Discover::Fetcher::XRI');
    use_ok('OpenID::Lite::RelyingParty::Discover::Fetcher::Yadis');
    use_ok('OpenID::Lite::RelyingParty::Discover::Fetcher::Yadis::HTMLExtractor');
    use_ok('OpenID::Lite::RelyingParty::Discover::Parser::XRI');
    use_ok('OpenID::Lite::RelyingParty::Discover::Parser::HTML');
    use_ok('OpenID::Lite::RelyingParty::Discover::Parser::XRDS');
    use_ok('OpenID::Lite::RelyingParty::Discover::Parser::Yadis');
    use_ok('OpenID::Lite::RelyingParty::Discover');

    # idres
    use_ok('OpenID::Lite::RelyingParty::IDResHandler');
    use_ok('OpenID::Lite::RelyingParty::IDResHandler::Verifier');

    # store
    use_ok('OpenID::Lite::RelyingParty::Store::Null');
    use_ok('OpenID::Lite::RelyingParty::Store::OnMemory');


    # association
    use_ok('OpenID::Lite::RelyingParty::Associator::Base');
    use_ok('OpenID::Lite::RelyingParty::Associator::ParamBuilder');
    use_ok('OpenID::Lite::RelyingParty::Associator::ParamExtractor');
    use_ok('OpenID::Lite::RelyingParty::Associator');

    # checkid
    use_ok('OpenID::Lite::RelyingParty::CheckID::Result');
    use_ok('OpenID::Lite::RelyingParty::CheckID::Request');

    use_ok('OpenID::Lite::RelyingParty');


    use_ok('OpenID::Lite::Provider::AssociationBuilder');
    use_ok('OpenID::Lite::Provider::Discover');
    use_ok('OpenID::Lite::Provider::Discover::Parser');
    use_ok('OpenID::Lite::Provider::Handler::Association');
    use_ok('OpenID::Lite::Provider::Handler::CheckAuth');
    use_ok('OpenID::Lite::Provider::Handler::CheckID');
    use_ok('OpenID::Lite::Provider::Response');
    use_ok('OpenID::Lite::Provider');
};



