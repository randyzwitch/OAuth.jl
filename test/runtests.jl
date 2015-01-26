using OAuth
using Base.Test



#Test that timestamp comes out as a string
@test typeof(oauth_timestamp()) <: String

#Test that timestamp is greater than integer representing approx. 2014-01-25 20:25:00
@test int(oauth_timestamp()) > 1422235471



#Test that nonce comes out as a string
@test typeof(oauth_nonce(15)) <: String

#Test that nonce comes out same length as passed argument
@test length(oauth_nonce(15)) == 15
@test length(oauth_nonce(20)) == 20
@test length(oauth_nonce(25)) == 25
@test length(oauth_nonce(30)) == 30
@test length(oauth_nonce(32)) == 32



#Test that HMAC-SHA1 signature provides consistent string
@test oauth_sign_hmac_sha1("randy","zwitch") == "WqKCG5iyhFiES3fWYVdWJWwinaY="



#Validate that signing key a concatenation of values, separated by &
@test oauth_signing_key("9djdj82h48djs9d2", "kkk9d7dh3k39sjv7") == "9djdj82h48djs9d2&kkk9d7dh3k39sjv7"



#Test that base string is concatenated then percent-encoded
@test oauth_signature_base_string("POST", "http://example.com", "?julia=fast&lang=elegant") == "POST&http%3A%2F%2Fexample.com&%3Fjulia%3Dfast%26lang%3Delegant"



#TODO
#oauth_percent_encode_keys()



#TODO
#oauth_serialize_url_parameters()



#TODO
#encodeURI()



#TODO
#oauth_body_hash_file(filename::String)



#TODO
#oauth_body_hash_data(data::String)



#TODO
#oauth_body_hash_encode(data::String)



#TODO
#oauth_header()



#TODO
#oauth_request_resource()